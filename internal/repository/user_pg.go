package repository

import (
	"context"
	"errors"
	"strings"

	"github.com/andruho/auth/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository interface {
	Create(ctx context.Context, username, email, passwordHash string) (domain.User, error)
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	VerifyEmail(ctx context.Context, id uuid.UUID) error
	UpdatePassword(ctx context.Context, id uuid.UUID, newHash string) error
	UpdateRole(ctx context.Context, id uuid.UUID, role string) error
}

type userRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) UserRepository {
	return &userRepo{pool: pool}
}

func (r *userRepo) Create(ctx context.Context, username, email, passwordHash string) (domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)
		 RETURNING id, username, email, password_hash, is_verified, role, created_at, updated_at`,
		username, email, passwordHash,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.IsVerified, &u.Role, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if strings.Contains(pgErr.ConstraintName, "username") {
				return domain.User{}, domain.ErrUsernameAlreadyExists
			}
			return domain.User{}, domain.ErrEmailAlreadyExists
		}
		return domain.User{}, err
	}
	return u, nil
}

func (r *userRepo) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx,
		`SELECT id, username, email, password_hash, is_verified, role, created_at, updated_at FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.IsVerified, &u.Role, &u.CreatedAt, &u.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, err
}

func (r *userRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx,
		`SELECT id, username, email, password_hash, is_verified, role, created_at, updated_at FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.IsVerified, &u.Role, &u.CreatedAt, &u.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, err
}

func (r *userRepo) VerifyEmail(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET is_verified = TRUE, updated_at = now() WHERE id = $1`, id)
	return err
}

func (r *userRepo) UpdatePassword(ctx context.Context, id uuid.UUID, newHash string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, newHash, id)
	return err
}

func (r *userRepo) UpdateRole(ctx context.Context, id uuid.UUID, role string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET role = $1, updated_at = now() WHERE id = $2`, role, id)
	return err
}
