package repository

import (
	"context"
	"github.com/a-aslani/golang_message_brokers/internal/user/entity"
)

type UserRepository interface {
	InsertUser(ctx context.Context, user *entity.User) error
	FindUserByEmail(ctx context.Context, email string) (*entity.User, error)
	FindUserByID(ctx context.Context, id string) (*entity.User, error)
}
