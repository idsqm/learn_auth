package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type TokenRepository interface {
	BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	StoreEmailVerification(ctx context.Context, token string, userID uuid.UUID) error
	GetEmailVerification(ctx context.Context, token string) (uuid.UUID, error)
	StorePasswordReset(ctx context.Context, token string, userID uuid.UUID) error
	GetPasswordReset(ctx context.Context, token string) (uuid.UUID, error)
}

type tokenRepo struct {
	rdb *redis.Client
}

func NewTokenRepository(rdb *redis.Client) TokenRepository {
	return &tokenRepo{rdb: rdb}
}

func (r *tokenRepo) BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error {
	return r.rdb.Set(ctx, blacklistKey(jti), "1", ttl).Err()
}

func (r *tokenRepo) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	n, err := r.rdb.Exists(ctx, blacklistKey(jti)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *tokenRepo) StoreEmailVerification(ctx context.Context, token string, userID uuid.UUID) error {
	return r.rdb.Set(ctx, emailVerifyKey(token), userID.String(), 24*time.Hour).Err()
}

func (r *tokenRepo) GetEmailVerification(ctx context.Context, token string) (uuid.UUID, error) {
	val, err := r.rdb.GetDel(ctx, emailVerifyKey(token)).Result()
	if err == redis.Nil {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(val)
}

func (r *tokenRepo) StorePasswordReset(ctx context.Context, token string, userID uuid.UUID) error {
	return r.rdb.Set(ctx, passwordResetKey(token), userID.String(), time.Hour).Err()
}

func (r *tokenRepo) GetPasswordReset(ctx context.Context, token string) (uuid.UUID, error) {
	val, err := r.rdb.GetDel(ctx, passwordResetKey(token)).Result()
	if err == redis.Nil {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(val)
}

func blacklistKey(jti string) string      { return fmt.Sprintf("blacklist:%s", jti) }
func emailVerifyKey(token string) string   { return fmt.Sprintf("email_verify:%s", token) }
func passwordResetKey(token string) string { return fmt.Sprintf("password_reset:%s", token) }
