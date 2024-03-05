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
	"github.com/a-aslani/golang_message_brokers/internal/user/infrastructure"
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

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := connectToMongodb(ctx, cfg.MongoDB.URI)
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	db := client.Database(cfg.MongoDB.Database)

	mongoRepo := infrastructure.NewMongoRepository(db, log)

	userService := service.NewUserService(mongoRepo, password.BcryptHashing{})

	tokenRepo := token.NewRedisRepository(cfg.Redis.Address, cfg.Redis.Password)

	jwt, err := token.NewHS256JWT(
		ctx,
		cfg,
		tokenRepo,
		time.Minute*time.Duration(20),
		time.Minute*time.Duration(3),
	)
	if err != nil {
		return err
	}

	primaryDriver := restapi.NewHandler(appData, log, jwt, cfg, userService)

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
