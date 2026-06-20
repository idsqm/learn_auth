package config

import (
	"context"
	"fmt"
	"time"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	ServerPort string `env:"SERVER_PORT,default=8080"`

	DBURL    string `env:"DB_URL,required"`
	RedisURL string `env:"REDIS_URL,required"`

	JWTSecret       string        `env:"JWT_SECRET,required"`
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL,default=15m"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL,default=168h"`

	SMTPHost string `env:"SMTP_HOST,default=localhost"`
	SMTPPort int    `env:"SMTP_PORT,default=1025"`
	SMTPFrom string `env:"SMTP_FROM,default=noreply@auth.local"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process(context.Background(), &cfg); err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return &cfg, nil
}
