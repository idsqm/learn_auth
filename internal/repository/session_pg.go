package repository

import (
	"context"
	"errors"

	"github.com/andruho/auth/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepository interface {
	Create(ctx context.Context, s domain.Session) error
	GetByID(ctx context.Context, id uuid.UUID) (domain.Session, error)
	GetByRefreshToken(ctx context.Context, token string) (domain.Session, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
}

type sessionRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) SessionRepository {
	return &sessionRepo{pool: pool}
}

func (r *sessionRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.Session, error) {
	var s domain.Session
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at
		 FROM sessions WHERE id = $1`, id,
	).Scan(&s.ID, &s.UserID, &s.RefreshToken, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, domain.ErrSessionNotFound
	}
	return s, err
}

func (r *sessionRepo) Create(ctx context.Context, s domain.Session) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, refresh_token, ip_address, user_agent, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		s.ID, s.UserID, s.RefreshToken, s.IPAddress, s.UserAgent, s.ExpiresAt,
	)
	return err
}

func (r *sessionRepo) GetByRefreshToken(ctx context.Context, token string) (domain.Session, error) {
	var s domain.Session
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at
		 FROM sessions WHERE refresh_token = $1`, token,
	).Scan(&s.ID, &s.UserID, &s.RefreshToken, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, domain.ErrSessionNotFound
	}
	return s, err
}

func (r *sessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, refresh_token, ip_address, user_agent, expires_at, created_at
		 FROM sessions WHERE user_id = $1 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []domain.Session
	for rows.Next() {
		var s domain.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.RefreshToken, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (r *sessionRepo) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}

func (r *sessionRepo) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}
