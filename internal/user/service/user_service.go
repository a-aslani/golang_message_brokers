package service

import (
	"context"
	"errors"
	"github.com/a-aslani/golang_message_brokers/internal/pkg/password"
	"github.com/a-aslani/golang_message_brokers/internal/user/entity"
	"github.com/a-aslani/golang_message_brokers/internal/user/errorenum"
	"github.com/a-aslani/golang_message_brokers/internal/user/repository"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
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

func (s UserService) GetUser(ctx context.Context, dto GetUserDTO) (*entity.User, error) {

	user, err := s.repo.FindUserByID(ctx, dto.UserID)
	if err != nil {
		return nil, err
	}

	return user, err
}

func (s UserService) Login(ctx context.Context, dto LoginDTO) (*entity.User, error) {

	user, err := s.repo.FindUserByEmail(ctx, dto.Email)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errorenum.ErrInvalidEmailAddress.Var(dto.Email)
		}
		return nil, err
	}

	check := s.hasher.CheckPasswordHash(dto.Password, user.Password)
	if !check {
		return nil, errorenum.ErrWrongPassword
	}

	return user, nil
}

func (s UserService) Register(ctx context.Context, dto RegisterDTO) error {

	user, _ := s.repo.FindUserByEmail(ctx, dto.Email)
	if user != nil {
		return errorenum.ErrAlreadyRegistered.Var(dto.Email)
	}

	hashedPassword, err := s.hasher.HashPassword(dto.Password)
	if err != nil {
		return err
	}

	err = s.repo.InsertUser(ctx, &entity.User{
		ID:        uuid.New().String(),
		FirstName: dto.FirstName,
		LastName:  dto.LastName,
		Email:     dto.Email,
		Password:  hashedPassword,
	})

	if err != nil {
		return err
	}

	return nil
}
