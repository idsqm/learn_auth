package domain

import (
	"errors"
	"fmt"
	"net/http"
)

type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
}

func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewAppError(code, message string, httpStatus int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus}
}

func IsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

var (
	ErrUnauthorized          = NewAppError("UNAUTHORIZED", "Unauthorized", http.StatusUnauthorized)
	ErrEmailAlreadyExists    = NewAppError("EMAIL_ALREADY_EXISTS", "An account with this email already exists", http.StatusConflict)
	ErrUsernameAlreadyExists = NewAppError("USERNAME_ALREADY_EXISTS", "This username is already taken", http.StatusConflict)
	ErrInvalidCredentials    = NewAppError("INVALID_CREDENTIALS", "Invalid email or password", http.StatusUnauthorized)
	ErrEmailNotVerified      = NewAppError("EMAIL_NOT_VERIFIED", "Please verify your email before logging in", http.StatusForbidden)
	ErrAccessTokenExpired    = NewAppError("ACCESS_TOKEN_EXPIRED", "Access token has expired", http.StatusUnauthorized)
	ErrAccessTokenInvalid    = NewAppError("ACCESS_TOKEN_INVALID", "Access token is invalid", http.StatusUnauthorized)
	ErrRefreshTokenExpired   = NewAppError("REFRESH_TOKEN_EXPIRED", "Refresh token has expired", http.StatusUnauthorized)
	ErrRefreshTokenRevoked   = NewAppError("REFRESH_TOKEN_REVOKED", "Refresh token has been revoked", http.StatusUnauthorized)
	ErrUserNotFound          = NewAppError("USER_NOT_FOUND", "User not found", http.StatusNotFound)
	ErrSessionNotFound       = NewAppError("SESSION_NOT_FOUND", "Session not found", http.StatusNotFound)
	ErrInvalidResetToken     = NewAppError("INVALID_RESET_TOKEN", "Password reset token is invalid or expired", http.StatusBadRequest)
	ErrInvalidVerifyToken    = NewAppError("INVALID_VERIFY_TOKEN", "Email verification token is invalid or expired", http.StatusBadRequest)
	ErrValidation            = NewAppError("VALIDATION_ERROR", "Invalid request data", http.StatusBadRequest)
	ErrInternal              = NewAppError("INTERNAL_ERROR", "Something went wrong", http.StatusInternalServerError)
)

type ValidationErrors struct {
	Fields map[string][]string
}

func (e *ValidationErrors) Error() string {
	return "validation error"
}

func NewValidationErrors() *ValidationErrors {
	return &ValidationErrors{Fields: make(map[string][]string)}
}

func (e *ValidationErrors) Add(field, code string) {
	e.Fields[field] = append(e.Fields[field], code)
}

func (e *ValidationErrors) HasErrors() bool {
	return len(e.Fields) > 0
}

func IsValidationErrors(err error) (*ValidationErrors, bool) {
	var ve *ValidationErrors
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
