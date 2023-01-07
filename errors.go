package errors

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ErrorType string

const (
	ErrNotFound       ErrorType = "ENTRY_NOT_FOUND_ERROR"
	ErrValidation     ErrorType = "VALIDATION_ERROR"
	ErrEntryExists    ErrorType = "ENTRY_EXISTS_ERROR"
	ErrEntryDeleted   ErrorType = "ENTRY_DELETED_ERROR"
	ErrAuthorization  ErrorType = "AUTHORIZATION_ERROR"
	ErrExpiredToken   ErrorType = "EXPIRED_TOKEN_ERROR"
	ErrAuthentication ErrorType = "AUTHENTICATION_ERROR"
	ErrInvalidToken   ErrorType = "INVALID_TOKEN_ERROR"
	ErrPermission     ErrorType = "PERMISSION_ERROR"
	ErrFatal          ErrorType = "FATAL_ERROR"
	ErrNotImplemented ErrorType = "NOT_IMPLEMENTED_ERROR"
)

type AppError struct {
	Code          int       `json:"-"`
	Type          ErrorType `json:"type"`
	Message       string    `json:"message"`
	Internal      string    `json:"internal"`
	InternalError error     `json:"-"`
}

func (a AppError) Error() string {
	return fmt.Sprintf("%s: %s", a.Type, a.Message)
}

func (a AppError) Serialize(c *gin.Context) {
	c.Error(a)
	c.AbortWithStatusJSON(a.Code, a)
}

func Is(err, target error) bool {
	return errors.Is(err, target)
}

func New(msg string) error {
	return errors.New(msg)
}

func Errorf(format string, vars ...interface{}) error {
	return fmt.Errorf(format, vars...)
}

func HandleMongoError(err error, ctx string) AppError {
	if _, ok := err.(mongo.WriteException); ok {
		return AppError{
			Code:          http.StatusConflict,
			Type:          ErrEntryExists,
			Message:       fmt.Sprintf("%s already exists", ctx),
			Internal:      err.Error(),
			InternalError: err,
		}
	}
	if Is(err, mongo.ErrNoDocuments) {
		return AppError{
			Code:          http.StatusNotFound,
			Type:          ErrNotFound,
			Message:       fmt.Sprintf("%s does not exist", ctx),
			Internal:      err.Error(),
			InternalError: err,
		}
	}
	return NewFatalError(err)
}

func HandleRPCError(err error) AppError {
	if sErr, ok := status.FromError(err); ok {
		switch sErr.Code() {
		case codes.Unknown, codes.Internal:
			return NewFatalError(New(sErr.Message()))
		case codes.NotFound:
			return NewNotFoundError(sErr.Message())
		case codes.InvalidArgument:
			return NewValidationError(sErr.Message())
		}
	}
	return NewFatalError(err)
}

func HandleBindError(err error) AppError {
	if v, ok := err.(validator.ValidationErrors); ok {
		message := fmt.Sprintf("Validation failed on field { %s }, Condition: %s", v[0].Field(), v[0].ActualTag())
		if v[0].Param() != "" {
			message += fmt.Sprintf("{ %s }", v[0].Param())
		}
		if v[0].Value() != "" {
			message += fmt.Sprintf(", Value Recieved: %v", v[0].Value())
		}

		return AppError{
			Code:     http.StatusBadRequest,
			Type:     ErrValidation,
			Message:  message,
			Internal: err.Error(),
		}
	}
	if Is(err, io.EOF) {
		return NewValidationError("No request body")
	}

	return NewFatalError(err)
}

func NewValidationError(msg string) AppError {
	return AppError{
		Code:    http.StatusBadRequest,
		Type:    ErrValidation,
		Message: msg,
	}
}

func NewNotFoundError(msg string) AppError {
	return AppError{
		Code:    http.StatusNotFound,
		Type:    ErrNotFound,
		Message: msg,
	}
}

func NewPermissionError(msg string) AppError {
	return AppError{
		Code:    http.StatusUnauthorized,
		Type:    ErrPermission,
		Message: msg,
	}
}

func NewInvalidTokenError() AppError {
	return AppError{
		Code:    http.StatusUnauthorized,
		Type:    ErrInvalidToken,
		Message: "Invalid token",
	}
}

func NewFatalError(err error) AppError {
	return AppError{
		Code:     http.StatusInternalServerError,
		Type:     ErrFatal,
		Message:  "Oops! something happened on our end.",
		Internal: err.Error(),
	}
}

func AsAppError(err error) AppError {
	apperr := new(AppError)
	if errors.As(err, apperr) {
		return *apperr
	}
	return NewFatalError(err)
}
