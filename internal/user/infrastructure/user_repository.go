package infrastructure

import (
	"context"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/logger"
	"github.com/a-aslani/golang_message_brokers/internal/user/entity"
	"github.com/a-aslani/golang_message_brokers/internal/user/repository"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoRepository struct {
	db  *mongo.Database
	log logger.Logger
}

var _ repository.UserRepository = (*MongoRepository)(nil)

func NewMongoRepository(db *mongo.Database, log logger.Logger) *MongoRepository {
	return &MongoRepository{
		log: log,
		db:  db,
	}
}

func (m MongoRepository) FindUserByID(ctx context.Context, id string) (*entity.User, error) {
	m.log.Info(ctx, "call")

	var user *entity.User

	filter := bson.D{{"_id", id}}

	if err := m.db.Collection("users").FindOne(ctx, filter).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}

func (m MongoRepository) InsertUser(ctx context.Context, user *entity.User) error {
	m.log.Info(ctx, "call")

	_, err := m.db.Collection("users").InsertOne(ctx, user)
	if err != nil {
		return err
	}

	return nil
}

func (m MongoRepository) FindUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	m.log.Info(ctx, "call")

	var user *entity.User

	filter := bson.D{{"email", email}}

	if err := m.db.Collection("users").FindOne(ctx, filter).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}
