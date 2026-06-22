package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/andruho/auth/internal/domain"
	"github.com/andruho/auth/internal/email"
	jwtpkg "github.com/andruho/auth/internal/pkg/jwt"
	"github.com/andruho/auth/internal/pkg/password"
	"github.com/andruho/auth/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthService interface {
	Register(ctx context.Context, username, email, password string) error
	VerifyEmail(ctx context.Context, token string) error
	Login(ctx context.Context, email, password, ip, userAgent string) (accessToken, refreshToken string, err error)
	Refresh(ctx context.Context, refreshToken, ip, userAgent string) (newAccess, newRefresh string, err error)
	Logout(ctx context.Context, sessionID uuid.UUID, accessToken string) error
	ListSessions(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	Me(ctx context.Context, userID uuid.UUID) (*domain.User, error)
}

type authService struct {
	users    repository.UserRepository
	sessions repository.SessionRepository
	tokens   repository.TokenRepository
	email    email.Sender
	jwt      *jwtpkg.Manager
	log      *slog.Logger
}

func NewAuthService(
	users repository.UserRepository,
	sessions repository.SessionRepository,
	tokens repository.TokenRepository,
	emailSender email.Sender,
	jwtManager *jwtpkg.Manager,
	log *slog.Logger,
) AuthService {
	return &authService{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		email:    emailSender,
		jwt:      jwtManager,
		log:      log,
	}
}

func (s *authService) Register(ctx context.Context, username, emailAddr, pwd string) error {
	hash, err := password.Hash(pwd)
	if err != nil {
		return err
	}

	user, err := s.users.Create(ctx, username, emailAddr, hash)
	if err != nil {
		return err
	}

	token, err := generateSecureToken()
	if err != nil {
		return err
	}

	if err := s.tokens.StoreEmailVerification(ctx, token, user.ID); err != nil {
		return err
	}

	if err := s.email.SendVerification(ctx, emailAddr, token); err != nil {
		s.log.Error("failed to send verification email", "email", emailAddr, "error", err)
	}

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	userID, err := s.tokens.GetEmailVerification(ctx, token)
	if err != nil {
		return err
	}
	if userID == uuid.Nil {
		return domain.ErrInvalidVerifyToken
	}

	return s.users.VerifyEmail(ctx, userID)
}

func (s *authService) Login(ctx context.Context, emailAddr, pwd, ip, userAgent string) (string, string, error) {
	user, err := s.users.GetByEmail(ctx, emailAddr)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", "", domain.ErrInvalidCredentials
		}
		return "", "", err
	}

	if !password.Compare(user.PasswordHash, pwd) {
		return "", "", domain.ErrInvalidCredentials
	}

	if !user.IsVerified {
		return "", "", domain.ErrEmailNotVerified
	}

	accessToken, err := s.jwt.GenerateAccessToken(user.ID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.jwt.GenerateRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	session := domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		RefreshToken: refreshToken,
		IPAddress:    ip,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(s.jwt.RefreshTokenTTL()),
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *authService) Refresh(ctx context.Context, refreshToken, ip, userAgent string) (string, string, error) {
	claims, err := s.jwt.Parse(refreshToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", "", domain.ErrRefreshTokenExpired
		}
		return "", "", domain.ErrRefreshTokenRevoked
	}

	blacklisted, err := s.tokens.IsBlacklisted(ctx, claims.ID)
	if err != nil {
		return "", "", err
	}
	if blacklisted {
		return "", "", domain.ErrRefreshTokenRevoked
	}

	session, err := s.sessions.GetByRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", "", domain.ErrRefreshTokenRevoked
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > 0 {
		if err := s.tokens.BlacklistToken(ctx, claims.ID, ttl); err != nil {
			return "", "", err
		}
	}

	if err := s.sessions.Delete(ctx, session.ID); err != nil {
		return "", "", err
	}

	newAccess, err := s.jwt.GenerateAccessToken(claims.UserID)
	if err != nil {
		return "", "", err
	}

	newRefresh, err := s.jwt.GenerateRefreshToken(claims.UserID)
	if err != nil {
		return "", "", err
	}

	newSession := domain.Session{
		ID:           uuid.New(),
		UserID:       claims.UserID,
		RefreshToken: newRefresh,
		IPAddress:    ip,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(s.jwt.RefreshTokenTTL()),
	}

	if err := s.sessions.Create(ctx, newSession); err != nil {
		return "", "", err
	}

	return newAccess, newRefresh, nil
}

func (s *authService) Logout(ctx context.Context, sessionID uuid.UUID, accessToken string) error {
	session, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}

	if accessClaims, err := s.jwt.Parse(accessToken); err == nil {
		if ttl := time.Until(accessClaims.ExpiresAt.Time); ttl > 0 {
			_ = s.tokens.BlacklistToken(ctx, accessClaims.ID, ttl)
		}
	}

	if refreshClaims, err := s.jwt.Parse(session.RefreshToken); err == nil {
		if ttl := time.Until(refreshClaims.ExpiresAt.Time); ttl > 0 {
			_ = s.tokens.BlacklistToken(ctx, refreshClaims.ID, ttl)
		}
	}

	return s.sessions.Delete(ctx, sessionID)
}

func (s *authService) ListSessions(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	return s.sessions.ListByUserID(ctx, userID)
}

func (s *authService) RequestPasswordReset(ctx context.Context, emailAddr string) error {
	user, err := s.users.GetByEmail(ctx, emailAddr)
	if err != nil {
		// Don't reveal whether email exists
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil
		}
		return err
	}

	token, err := generateSecureToken()
	if err != nil {
		return err
	}

	if err := s.tokens.StorePasswordReset(ctx, token, user.ID); err != nil {
		return err
	}

	if err := s.email.SendPasswordReset(ctx, emailAddr, token); err != nil {
		s.log.Error("failed to send password reset email", "email", emailAddr, "error", err)
	}

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	userID, err := s.tokens.GetPasswordReset(ctx, token)
	if err != nil {
		return err
	}
	if userID == uuid.Nil {
		return domain.ErrInvalidResetToken
	}

	hash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}

	if err := s.users.UpdatePassword(ctx, userID, hash); err != nil {
		return err
	}

	_ = s.sessions.DeleteAllForUser(ctx, userID)

	return nil
}

func (s *authService) Me(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
