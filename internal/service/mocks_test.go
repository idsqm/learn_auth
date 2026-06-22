package service

import (
	"context"
	"time"

	"github.com/andruho/auth/internal/domain"
	"github.com/google/uuid"
)

type mockUserRepo struct {
	createFn         func(ctx context.Context, username, email, passwordHash string) (domain.User, error)
	getByEmailFn     func(ctx context.Context, email string) (domain.User, error)
	getByIDFn        func(ctx context.Context, id uuid.UUID) (domain.User, error)
	verifyEmailFn    func(ctx context.Context, id uuid.UUID) error
	updatePasswordFn func(ctx context.Context, id uuid.UUID, newHash string) error
}

func (m *mockUserRepo) Create(ctx context.Context, username, email, passwordHash string) (domain.User, error) {
	return m.createFn(ctx, username, email, passwordHash)
}
func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	return m.getByEmailFn(ctx, email)
}
func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return m.getByIDFn(ctx, id)
}
func (m *mockUserRepo) VerifyEmail(ctx context.Context, id uuid.UUID) error {
	return m.verifyEmailFn(ctx, id)
}
func (m *mockUserRepo) UpdatePassword(ctx context.Context, id uuid.UUID, newHash string) error {
	return m.updatePasswordFn(ctx, id, newHash)
}

type mockSessionRepo struct {
	createFn           func(ctx context.Context, s domain.Session) error
	getByIDFn          func(ctx context.Context, id uuid.UUID) (domain.Session, error)
	getByRefreshFn     func(ctx context.Context, token string) (domain.Session, error)
	listByUserIDFn     func(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
	deleteFn           func(ctx context.Context, id uuid.UUID) error
	deleteAllForUserFn func(ctx context.Context, userID uuid.UUID) error
}

func (m *mockSessionRepo) Create(ctx context.Context, s domain.Session) error {
	return m.createFn(ctx, s)
}
func (m *mockSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.Session, error) {
	return m.getByIDFn(ctx, id)
}
func (m *mockSessionRepo) GetByRefreshToken(ctx context.Context, token string) (domain.Session, error) {
	return m.getByRefreshFn(ctx, token)
}
func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	return m.listByUserIDFn(ctx, userID)
}
func (m *mockSessionRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.deleteFn(ctx, id)
}
func (m *mockSessionRepo) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	return m.deleteAllForUserFn(ctx, userID)
}

type mockTokenRepo struct {
	blacklistFn      func(ctx context.Context, jti string, ttl time.Duration) error
	isBlacklistedFn  func(ctx context.Context, jti string) (bool, error)
	storeEmailFn     func(ctx context.Context, token string, userID uuid.UUID) error
	getEmailFn       func(ctx context.Context, token string) (uuid.UUID, error)
	storePasswordFn  func(ctx context.Context, token string, userID uuid.UUID) error
	getPasswordFn    func(ctx context.Context, token string) (uuid.UUID, error)
}

func (m *mockTokenRepo) BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error {
	return m.blacklistFn(ctx, jti, ttl)
}
func (m *mockTokenRepo) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	return m.isBlacklistedFn(ctx, jti)
}
func (m *mockTokenRepo) StoreEmailVerification(ctx context.Context, token string, userID uuid.UUID) error {
	return m.storeEmailFn(ctx, token, userID)
}
func (m *mockTokenRepo) GetEmailVerification(ctx context.Context, token string) (uuid.UUID, error) {
	return m.getEmailFn(ctx, token)
}
func (m *mockTokenRepo) StorePasswordReset(ctx context.Context, token string, userID uuid.UUID) error {
	return m.storePasswordFn(ctx, token, userID)
}
func (m *mockTokenRepo) GetPasswordReset(ctx context.Context, token string) (uuid.UUID, error) {
	return m.getPasswordFn(ctx, token)
}

type mockEmailSender struct {
	sendVerificationFn   func(ctx context.Context, to, token string) error
	sendPasswordResetFn  func(ctx context.Context, to, token string) error
}

func (m *mockEmailSender) SendVerification(ctx context.Context, to, token string) error {
	return m.sendVerificationFn(ctx, to, token)
}
func (m *mockEmailSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return m.sendPasswordResetFn(ctx, to, token)
}
