package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/andruho/auth/internal/domain"
	jwtpkg "github.com/andruho/auth/internal/pkg/jwt"
	"github.com/andruho/auth/internal/pkg/password"
	"github.com/google/uuid"
)

func newTestService(users *mockUserRepo, sessions *mockSessionRepo, tokens *mockTokenRepo, emailSender *mockEmailSender) AuthService {
	jwtManager := jwtpkg.NewManager("test-secret", 15*time.Minute, 7*24*time.Hour)
	return NewAuthService(users, sessions, tokens, emailSender, jwtManager, slog.Default())
}

func TestRegister_Success(t *testing.T) {
	userID := uuid.New()
	users := &mockUserRepo{
		createFn: func(_ context.Context, username, email, hash string) (domain.User, error) {
			return domain.User{ID: userID, Username: username, Email: email}, nil
		},
	}
	tokens := &mockTokenRepo{
		storeEmailFn: func(_ context.Context, _ string, id uuid.UUID) error {
			if id != userID {
				t.Errorf("expected userID %s, got %s", userID, id)
			}
			return nil
		},
	}
	emailSender := &mockEmailSender{
		sendVerificationFn: func(_ context.Context, to, token string) error {
			if to == "" || token == "" {
				t.Error("expected non-empty to and token")
			}
			return nil
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, tokens, emailSender)
	err := svc.Register(context.Background(), "testuser", "test@example.com", "password123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	users := &mockUserRepo{
		createFn: func(_ context.Context, _, _, _ string) (domain.User, error) {
			return domain.User{}, domain.ErrEmailAlreadyExists
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, &mockTokenRepo{}, &mockEmailSender{})
	err := svc.Register(context.Background(), "testuser", "test@example.com", "password123")
	if !errors.Is(err, domain.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestLogin_Success(t *testing.T) {
	userID := uuid.New()
	// bcrypt hash of "password123"
	users := &mockUserRepo{
		getByEmailFn: func(_ context.Context, _ string) (domain.User, error) {
			return domain.User{
				ID:           userID,
				Email:        "test@example.com",
				PasswordHash: hashForTest(t, "password123"),
				IsVerified:   true,
			}, nil
		},
	}
	sessions := &mockSessionRepo{
		createFn: func(_ context.Context, s domain.Session) error {
			if s.UserID != userID {
				t.Errorf("expected userID %s, got %s", userID, s.UserID)
			}
			return nil
		},
	}

	svc := newTestService(users, sessions, &mockTokenRepo{}, &mockEmailSender{})
	access, refresh, err := svc.Login(context.Background(), "test@example.com", "password123", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}
}

func TestLogin_InvalidPassword(t *testing.T) {
	users := &mockUserRepo{
		getByEmailFn: func(_ context.Context, _ string) (domain.User, error) {
			return domain.User{
				ID:           uuid.New(),
				PasswordHash: hashForTest(t, "correct-password"),
				IsVerified:   true,
			}, nil
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, &mockTokenRepo{}, &mockEmailSender{})
	_, _, err := svc.Login(context.Background(), "test@example.com", "wrong-password", "127.0.0.1", "TestAgent")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	users := &mockUserRepo{
		getByEmailFn: func(_ context.Context, _ string) (domain.User, error) {
			return domain.User{}, domain.ErrUserNotFound
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, &mockTokenRepo{}, &mockEmailSender{})
	_, _, err := svc.Login(context.Background(), "nobody@example.com", "password123", "127.0.0.1", "TestAgent")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_EmailNotVerified(t *testing.T) {
	users := &mockUserRepo{
		getByEmailFn: func(_ context.Context, _ string) (domain.User, error) {
			return domain.User{
				ID:           uuid.New(),
				PasswordHash: hashForTest(t, "password123"),
				IsVerified:   false,
			}, nil
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, &mockTokenRepo{}, &mockEmailSender{})
	_, _, err := svc.Login(context.Background(), "test@example.com", "password123", "127.0.0.1", "TestAgent")
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestVerifyEmail_Success(t *testing.T) {
	userID := uuid.New()
	tokens := &mockTokenRepo{
		getEmailFn: func(_ context.Context, _ string) (uuid.UUID, error) {
			return userID, nil
		},
	}
	users := &mockUserRepo{
		verifyEmailFn: func(_ context.Context, id uuid.UUID) error {
			if id != userID {
				t.Errorf("expected %s, got %s", userID, id)
			}
			return nil
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, tokens, &mockEmailSender{})
	err := svc.VerifyEmail(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	tokens := &mockTokenRepo{
		getEmailFn: func(_ context.Context, _ string) (uuid.UUID, error) {
			return uuid.Nil, nil
		},
	}

	svc := newTestService(&mockUserRepo{}, &mockSessionRepo{}, tokens, &mockEmailSender{})
	err := svc.VerifyEmail(context.Background(), "invalid-token")
	if !errors.Is(err, domain.ErrInvalidVerifyToken) {
		t.Fatalf("expected ErrInvalidVerifyToken, got %v", err)
	}
}

func TestRefresh_BlacklistedToken(t *testing.T) {
	jwtManager := jwtpkg.NewManager("test-secret", 15*time.Minute, 7*24*time.Hour)
	userID := uuid.New()
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID, "student")

	tokens := &mockTokenRepo{
		isBlacklistedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}

	svc := NewAuthService(&mockUserRepo{}, &mockSessionRepo{}, tokens, &mockEmailSender{}, jwtManager, slog.Default())
	_, _, err := svc.Refresh(context.Background(), refreshToken, "127.0.0.1", "TestAgent")
	if !errors.Is(err, domain.ErrRefreshTokenRevoked) {
		t.Fatalf("expected ErrRefreshTokenRevoked, got %v", err)
	}
}

func TestRequestPasswordReset_UnknownEmail(t *testing.T) {
	users := &mockUserRepo{
		getByEmailFn: func(_ context.Context, _ string) (domain.User, error) {
			return domain.User{}, domain.ErrUserNotFound
		},
	}

	svc := newTestService(users, &mockSessionRepo{}, &mockTokenRepo{}, &mockEmailSender{})
	err := svc.RequestPasswordReset(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("expected nil (don't reveal email existence), got %v", err)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	tokens := &mockTokenRepo{
		getPasswordFn: func(_ context.Context, _ string) (uuid.UUID, error) {
			return uuid.Nil, nil
		},
	}

	svc := newTestService(&mockUserRepo{}, &mockSessionRepo{}, tokens, &mockEmailSender{})
	err := svc.ResetPassword(context.Background(), "bad-token", "newpassword123")
	if !errors.Is(err, domain.ErrInvalidResetToken) {
		t.Fatalf("expected ErrInvalidResetToken, got %v", err)
	}
}

func TestResetPassword_Success(t *testing.T) {
	userID := uuid.New()
	tokens := &mockTokenRepo{
		getPasswordFn: func(_ context.Context, _ string) (uuid.UUID, error) {
			return userID, nil
		},
	}
	users := &mockUserRepo{
		updatePasswordFn: func(_ context.Context, id uuid.UUID, _ string) error {
			if id != userID {
				t.Errorf("expected %s, got %s", userID, id)
			}
			return nil
		},
	}
	sessions := &mockSessionRepo{
		deleteAllForUserFn: func(_ context.Context, id uuid.UUID) error {
			if id != userID {
				t.Errorf("expected %s, got %s", userID, id)
			}
			return nil
		},
	}

	svc := newTestService(users, sessions, tokens, &mockEmailSender{})
	err := svc.ResetPassword(context.Background(), "valid-token", "newpassword123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func hashForTest(t *testing.T, pwd string) string {
	t.Helper()
	h, err := password.Hash(pwd)
	if err != nil {
		t.Fatalf("failed to hash: %v", err)
	}
	return h
}
