package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/andruho/auth/internal/domain"
)

var (
	logger    *slog.Logger = slog.Default()
	debugMode bool
)

func SetLogger(l *slog.Logger, debug bool) {
	logger = l
	debugMode = debug
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type validationResponse struct {
	Errors map[string][]string `json:"errors"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	if ve, ok := domain.IsValidationErrors(err); ok {
		writeJSON(w, http.StatusUnprocessableEntity, validationResponse{Errors: ve.Fields})
		return
	}

	if appErr, ok := domain.IsAppError(err); ok {
		writeJSON(w, appErr.HTTPStatus, errorResponse{
			Error: errorBody{Code: appErr.Code, Message: appErr.Message},
		})
		return
	}

	logger.Error("internal error", "error", err.Error())

	msg := domain.ErrInternal.Message
	if debugMode {
		msg = err.Error()
	}

	writeJSON(w, http.StatusInternalServerError, errorResponse{
		Error: errorBody{Code: domain.ErrInternal.Code, Message: msg},
	})
}

func writeOK(w http.ResponseWriter, v any) {
	writeJSON(w, http.StatusOK, v)
}
