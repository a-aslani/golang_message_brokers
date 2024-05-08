package main

import (
	"encoding/json"
	"fmt"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework/pubsub"
	event2 "github.com/a-aslani/golang_message_brokers/internal/user/event"
	"github.com/mitchellh/mapstructure"
	amqp "github.com/rabbitmq/amqp091-go"
)

func main() {

	const appName = "product"

	event, err := pubsub.NewEvent(appName, "guest", "guest", "localhost", "")
	if err != nil {
		panic(event)
	}

	bindings := []pubsub.ConsumerOptionsBinding{
		{ExchangeName: "user.event", RoutingKey: "v1.user.created"},
	}

	event.SetConsumer("quetest", bindings)

	event.Consume(func(i int64, msg *amqp.Delivery) {

		var eventData pubsub.EventData

		err := json.Unmarshal(msg.Body, &eventData)
		if err != nil {
			fmt.Println(err)
		}

		switch eventData.Name {
		case event2.UserCreated:
			var user event2.UserCreatedData
			err := mapstructure.Decode(eventData.Payload, &user)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(user)
			break
		}

		//fmt.Println(fmt.Sprintf("consumed message [ID=%d, EX=%s, RK=%s] %s", i, msg.Exchange, msg.RoutingKey, string(msg.Body)))

		// simulate timeout
		// time.Sleep(100 * time.Second)

		//if i%10 == 0 {
		//	fmt.Println("reject-----------")
		//	msg.Reject(false)
		//} else {
		//	fmt.Println("ack---------------")
		//	msg.Ack(false)
		//}
	})
}
