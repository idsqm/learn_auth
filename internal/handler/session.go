package handler

import (
	"net/http"

	"github.com/andruho/auth/internal/service"
)

type SessionHandler struct {
	auth service.AuthService
}

func NewSessionHandler(auth service.AuthService) *SessionHandler {
	return &SessionHandler{auth: auth}
}

func (h *SessionHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	sessions, err := h.auth.ListSessions(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, map[string]any{"sessions": sessions})
}
