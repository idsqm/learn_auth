package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/andruho/auth/internal/domain"
	"github.com/andruho/auth/internal/service"
	"github.com/google/uuid"
)

type AuthHandler struct {
	auth service.AuthService
}

func NewAuthHandler(auth service.AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	ve := domain.NewValidationErrors()
	if req.Username == "" {
		ve.Add("username", "required")
	}
	if req.Email == "" {
		ve.Add("email", "required")
	}
	if req.Password == "" {
		ve.Add("password", "required")
	} else if len(req.Password) < 8 {
		ve.Add("password", "min:8")
	}
	if ve.HasErrors() {
		writeError(w, ve)
		return
	}

	if err := h.auth.Register(r.Context(), req.Username, req.Email, req.Password); err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyExists) {
			ve.Add("email", "unique")
			writeError(w, ve)
			return
		}
		if errors.Is(err, domain.ErrUsernameAlreadyExists) {
			ve.Add("username", "unique")
			writeError(w, ve)
			return
		}
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "Registration successful. Please check your email."})
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	if req.Token == "" {
		ve := domain.NewValidationErrors()
		ve.Add("token", "required")
		writeError(w, ve)
		return
	}

	if err := h.auth.VerifyEmail(r.Context(), req.Token); err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, map[string]string{"message": "Email verified successfully"})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	ve := domain.NewValidationErrors()
	if req.Email == "" {
		ve.Add("email", "required")
	}
	if req.Password == "" {
		ve.Add("password", "required")
	}
	if ve.HasErrors() {
		writeError(w, ve)
		return
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}

	access, refresh, err := h.auth.Login(r.Context(), req.Email, req.Password, ip, r.UserAgent())
	if err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, tokenResponse{AccessToken: access, RefreshToken: refresh})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	if req.RefreshToken == "" {
		ve := domain.NewValidationErrors()
		ve.Add("refresh_token", "required")
		writeError(w, ve)
		return
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}

	access, refresh, err := h.auth.Refresh(r.Context(), req.RefreshToken, ip, r.UserAgent())
	if err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, tokenResponse{AccessToken: access, RefreshToken: refresh})
}

type logoutRequest struct {
	SessionID string `json:"session_id"`
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	ve := domain.NewValidationErrors()
	if req.SessionID == "" {
		ve.Add("session_id", "required")
		writeError(w, ve)
		return
	}

	sessionID, err := uuid.Parse(req.SessionID)
	if err != nil {
		ve.Add("session_id", "uuid")
		writeError(w, ve)
		return
	}

	if err := h.auth.Logout(r.Context(), sessionID); err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, map[string]string{"message": "Logged out successfully"})
}

type resetRequestBody struct {
	Email string `json:"email"`
}

func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req resetRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	if req.Email == "" {
		ve := domain.NewValidationErrors()
		ve.Add("email", "required")
		writeError(w, ve)
		return
	}

	if err := h.auth.RequestPasswordReset(r.Context(), req.Email); err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, map[string]string{"message": "If an account exists, a password reset email has been sent."})
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrValidation)
		return
	}

	ve := domain.NewValidationErrors()
	if req.Token == "" {
		ve.Add("token", "required")
	}
	if req.NewPassword == "" {
		ve.Add("new_password", "required")
	} else if len(req.NewPassword) < 8 {
		ve.Add("new_password", "min:8")
	}
	if ve.HasErrors() {
		writeError(w, ve)
		return
	}

	if err := h.auth.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		writeError(w, err)
		return
	}

	writeOK(w, map[string]string{"message": "Password has been reset successfully"})
}
