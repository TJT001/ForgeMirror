package store

import (
	"context"
	"encoding/json"
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
	AppPackage string            `json:"app_package"`
	Detection  bool              `json:"detection"`
	Response   string            `json:"response"`
	Policies   map[string]string `json:"policies"`
}

func (s *Store) GetClientConfig(ctx context.Context, appPackage string) (ClientConfig, error) {
	config := ClientConfig{
		AppPackage: appPackage,
		Detection:  true,
		Response:   "toast",
		Policies:   map[string]string{},
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT detection, response, policies FROM client_config WHERE app_package = $1`,
		appPackage).Scan(&config.Detection, &config.Response, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return config, nil
	}
	if err != nil {
		return ClientConfig{}, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &config.Policies); err != nil {
			config.Policies = map[string]string{}
		}
	}
	return config, nil
}

func (s *Store) SetClientConfig(ctx context.Context, config ClientConfig) error {
	policies := config.Policies
	if policies == nil {
		policies = map[string]string{}
	}
	raw, err := json.Marshal(policies)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO client_config (app_package, detection, response, policies)
		VALUES ($1, $2, $3, $4::jsonb)
		ON CONFLICT (app_package) DO UPDATE
		SET detection = EXCLUDED.detection, response = EXCLUDED.response,
		    policies = EXCLUDED.policies, updated_at = now()`,
		config.AppPackage, config.Detection, config.Response, raw)
	return err
}
