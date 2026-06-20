package handler

import (
	"net/http"

	"github.com/andruho/auth/internal/pkg/jwt"
	"github.com/andruho/auth/internal/repository"
	"github.com/andruho/auth/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(authSvc service.AuthService, jwtManager *jwt.Manager, tokens repository.TokenRepository) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	auth := NewAuthHandler(authSvc)
	sessions := NewSessionHandler(authSvc)

	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", auth.Register)
		r.Post("/verify-email", auth.VerifyEmail)
		r.Post("/login", auth.Login)
		r.Post("/refresh", auth.Refresh)

		r.Post("/password/reset-request", auth.RequestPasswordReset)
		r.Post("/password/reset", auth.ResetPassword)

		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(jwtManager, tokens))
			r.Post("/logout", auth.Logout)
			r.Get("/sessions", sessions.List)
		})
	})

	return r
}
