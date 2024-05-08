package rabbitmq

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitClient is used to keep track of the RabbitMQ connection
type RabbitClient struct {
	// The connection that is used
	conn *amqp.Connection
	// The channel that processes/sends Messages
	ch *amqp.Channel
}

// NewRabbitMQClient will connect and return a Rabbitclient with an open connection
// Accepts a amqp Connection to be reused, to avoid spawning one TCP connection per concurrent client
func NewRabbitMQClient(conn *amqp.Connection) (RabbitClient, error) {
	// Unique, Conncurrent Server Channel to process/send messages
	// A good rule of thumb is to always REUSE Conn across applications
	// But spawn a new Channel per routine
	ch, err := conn.Channel()
	if err != nil {
		return RabbitClient{}, err
	}

	return RabbitClient{
		conn: conn,
		ch:   ch,
	}, nil
}

// Close will close the channel
func (rc RabbitClient) Close() error {
	return rc.ch.Close()
}

func (rc RabbitClient) QueueDeclare() (amqp.Queue, error) {

	return rc.ch.QueueDeclare("events", true, false, false, true, amqp.Table{
		"x-queue-type":                    "stream",
		"x-stream-max-segment-size-bytes": 30000,  // EACH SEGMENT FILE IS ALLOWED 0.03 MB
		"x-max-length-bytes":              150000, // TOTAL STREAM SIZE IS 0.15 MB
	})
}

func (rc RabbitClient) Publish(ctx context.Context, event Event) error {

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	payload := amqp.Publishing{
		DeliveryMode:  amqp.Persistent,
		ContentType:   "application/json",
		Body:          data,
		CorrelationId: uuid.NewString(),
	}

	return rc.ch.PublishWithContext(ctx, "", "events", false, false, payload)
}

func (rc RabbitClient) Subscribe(q string) (<-chan amqp.Delivery, error) {
	ch, err := rc.conn.Channel()
	if err != nil {
		return nil, err
	}
	defer ch.Close()

	return ch.Consume(q, "", false, false, false, false, nil)
}
