package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type RulePackage struct {
	ID         int64     `json:"id"`
	AppPackage string    `json:"app_package"`
	Version    int       `json:"version"`
	SHA256     string    `json:"sha256"`
	Path       string    `json:"path"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Store) PublishRulePackage(ctx context.Context, appPackage string,
	version int, sha256, path string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rule_packages (app_package, version, sha256, path)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (app_package, version) DO UPDATE
		SET sha256 = EXCLUDED.sha256, path = EXCLUDED.path, created_at = now()`,
		appPackage, version, sha256, path)
	return err
}

func (s *Store) LatestRulePackage(ctx context.Context, appPackage string) (*RulePackage, error) {
	var rule RulePackage
	err := s.pool.QueryRow(ctx, `
		SELECT id, app_package, version, sha256, path, created_at
		FROM rule_packages
		WHERE app_package = $1
		ORDER BY version DESC
		LIMIT 1`, appPackage).Scan(
		&rule.ID, &rule.AppPackage, &rule.Version, &rule.SHA256, &rule.Path,
		&rule.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

type ClientConfig struct {
	AppPackage string `json:"app_package"`
	Detection  bool   `json:"detection"`
	Response   string `json:"response"`
}

func (s *Store) GetClientConfig(ctx context.Context, appPackage string) (ClientConfig, error) {
	config := ClientConfig{AppPackage: appPackage, Detection: true, Response: "toast"}
	err := s.pool.QueryRow(ctx, `
		SELECT detection, response FROM client_config WHERE app_package = $1`,
		appPackage).Scan(&config.Detection, &config.Response)
	if errors.Is(err, pgx.ErrNoRows) {
		return config, nil
	}
	if err != nil {
		return ClientConfig{}, err
	}
	return config, nil
}

func (s *Store) SetClientConfig(ctx context.Context, config ClientConfig) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO client_config (app_package, detection, response)
		VALUES ($1, $2, $3)
		ON CONFLICT (app_package) DO UPDATE
		SET detection = EXCLUDED.detection, response = EXCLUDED.response,
		    updated_at = now()`,
		config.AppPackage, config.Detection, config.Response)
	return err
}
