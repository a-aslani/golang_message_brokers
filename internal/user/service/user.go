package service

import (
	"context"
	"errors"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/password"
	"github.com/a-aslani/golang_message_brokers/internal/user/entity"
	"github.com/a-aslani/golang_message_brokers/internal/user/repository"
	"github.com/google/uuid"
)

type UserService struct {
	repo   repository.UserRepository
	hasher password.Hasher
}

func NewUserService(repo repository.UserRepository, hasher password.Hasher) UserService {
	return UserService{
		repo:   repo,
		hasher: hasher,
	}
}

func (s UserService) Login(ctx context.Context, email, password string) (*entity.User, error) {

	user, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	check := s.hasher.CheckPasswordHash(password, user.Password)
	if !check {
		return nil, errors.New("wrong password")
	}

	return user, nil
}

func (s UserService) Register(ctx context.Context, firstName, lastName, email, password string) error {

	hashedPassword, err := s.hasher.HashPassword(password)
	if err != nil {
		return err
	}

	err = s.repo.InsertUser(ctx, &entity.User{
		ID:        uuid.New().String(),
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Password:  hashedPassword,
	})

	if err != nil {
		return err
	}

	return nil
}
