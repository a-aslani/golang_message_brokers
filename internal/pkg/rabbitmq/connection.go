package rabbitmq

import (
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
)

// ConnectRabbitMQ will spawn a Connection
func ConnectRabbitMQ(username, password, host, vhost string) (*amqp.Connection, error) {
	// Setup the Connection to RabbitMQ host using AMQP
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s/%s", username, password, host, vhost))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
