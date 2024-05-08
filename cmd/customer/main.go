package main

import (
	"flag"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework/pubsub"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/samber/lo"
	"github.com/samber/mo"
)

var rabbitmqURI = flag.String("rabbitmq-uri", "amqp://guest:guest@localhost:5672", "RabbitMQ URI")

const (
	queueName string = "product.onEdit"

	routingKeyProductCreated string = "product.created"
	routingKeyProductUpdated string = "product.updated"
	routingKeyProductRemoved string = "product.removed"
)

func main() {
	flag.Parse()

	if rabbitmqURI == nil {
		log.Println("missing --rabbitmiq-uri parameter")
	}

	conn, err := pubsub.NewConnection("example-connection-1", pubsub.ConnectionOptions{
		URI: *rabbitmqURI,
		Config: amqp.Config{
			Dial:      amqp.DefaultDial(time.Second),
			Heartbeat: time.Second,
		},
		LazyConnection: mo.Some(true),
	})
	if err != nil {
		// We ignore error, since it will reconnect automatically when available.
		// panic(err)
	}

	consumer := pubsub.NewConsumer(conn, "example-consumer-1", pubsub.ConsumerOptions{
		Queue: pubsub.ConsumerOptionsQueue{
			Name: queueName,
		},
		Bindings: []pubsub.ConsumerOptionsBinding{
			// crud
			{ExchangeName: "product.event", RoutingKey: "product.created"},
			{ExchangeName: "product.event", RoutingKey: "product.updated"},
			{ExchangeName: "user.event", RoutingKey: "user.created"},
		},
		Message: pubsub.ConsumerOptionsMessage{
			PrefetchCount: mo.Some(1000),
		},
		EnableDeadLetter: mo.Some(true),
	})

	log.Println("***** Let's go! ***** ")

	consumeMessages(consumer)

	log.Println("***** Finished! ***** ")

	consumer.Close()
	conn.Close()

	log.Println("***** Closed! ***** ")
}

func consumeMessages(consumer *pubsub.Consumer) {
	// Feel free to kill RabbitMQ and restart it, to see what happens ;)
	//		- docker-compose kill rabbitmq
	//		- docker-compose up rabbitmq

	channel := consumer.Consume()

	i := 0
	for msg := range channel {
		lo.Try0(func() { // handle exceptions
			consumeMessage(i, msg)
		})

		i++
	}
}

func consumeMessage(index int, msg *amqp.Delivery) {
	log.Println("consumed message [ID=%d, EX=%s, RK=%s] %s", index, msg.Exchange, msg.RoutingKey, string(msg.Body))

	// simulate timeout
	// time.Sleep(100 * time.Second)

	if index%10 == 0 {
		msg.Reject(false)
	} else {
		msg.Ack(false)
	}
}
