package errorenum

import "github.com/a-aslani/golang_message_brokers/internal/pkg/framework/model/apperror"

const (
	ErrInvalidEmailAddress apperror.ErrorType = "ER0001 %s is invalid email address"
	ErrWrongPassword       apperror.ErrorType = "ER0002 wrong password"
	ErrAlreadyRegistered   apperror.ErrorType = "ER0003 %s already registered"
)
