package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/andruho/auth/internal/domain"
	jwtpkg "github.com/andruho/auth/internal/pkg/jwt"
	"github.com/andruho/auth/internal/repository"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ctxKey string

const userIDKey ctxKey = "user_id"

func UserIDFromContext(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(userIDKey).(uuid.UUID)
	return id
}

func AuthMiddleware(jwtManager *jwtpkg.Manager, tokens repository.TokenRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				writeError(w, domain.ErrAccessTokenInvalid)
				return
			}

			token, found := strings.CutPrefix(header, "Bearer ")
			if !found {
				writeError(w, domain.ErrAccessTokenInvalid)
				return
			}

			claims, err := jwtManager.Parse(token)
			if err != nil {
				if errors.Is(err, jwtlib.ErrTokenExpired) {
					writeError(w, domain.ErrAccessTokenExpired)
				} else {
					writeError(w, domain.ErrAccessTokenInvalid)
				}
				return
			}

			blacklisted, err := tokens.IsBlacklisted(r.Context(), claims.ID)
			if err != nil {
				writeError(w, domain.ErrInternal)
				return
			}
			if blacklisted {
				writeError(w, domain.ErrAccessTokenInvalid)
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
