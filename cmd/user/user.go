package user

import (
	"context"
	"fmt"
	"github.com/a-aslani/golang_message_brokers/configs"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/framework"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/logger"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/password"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/token"
	"github.com/a-aslani/golang_message_brokers/internal/user/endpoint/restapi"
	"github.com/a-aslani/golang_message_brokers/internal/user/infrastructure/user_repository"
	"github.com/a-aslani/golang_message_brokers/internal/user/service"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type user struct{}

func NewUser() framework.Runner {
	return &user{}
}

func (user) Run(cfg *configs.Config) error {

	const appName = "user"

	fmt.Println(cfg.Servers[appName].Address)

	appData := framework.NewApplicationData(appName)

	log := logger.NewSimpleJSONLogger(appData)

	jwtToken := token.NewJWTToken(cfg.JWTSecretKey)

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := connectToMongodb(ctx, cfg.Servers[appName].MongoDB.URI)
	defer client.Disconnect(ctx)

	database := client.Database(cfg.Servers[appName].MongoDB.Database)

	mongoRepo := user_repository.NewMongoRepository(database, log)
	if err != nil {
		return err
	}

	userService := service.NewUserService(mongoRepo, password.BcryptHashing{})

	primaryDriver := restapi.NewHandler(appData, log, jwtToken, cfg, userService)

	primaryDriver.Start()

	return nil
}

func connectToMongodb(ctx context.Context, uri string) (*mongo.Client, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	return client, nil
}
