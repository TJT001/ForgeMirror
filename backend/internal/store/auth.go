package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type Grant struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"device_id"`
	TaskID     string    `json:"task_id"`
	WrappedKey []byte    `json:"-"`
	ExpiresAt  time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Store) UpsertDevice(ctx context.Context, deviceID string, publicKey []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (device_id, public_key_der)
		VALUES ($1, $2)
		ON CONFLICT (device_id) DO UPDATE
		SET public_key_der = EXCLUDED.public_key_der, updated_at = now()`,
		deviceID, publicKey)
	return err
}

func (s *Store) GetDevice(ctx context.Context, deviceID string) ([]byte, error) {
	var publicKey []byte
	err := s.pool.QueryRow(ctx,
		`SELECT public_key_der FROM devices WHERE device_id = $1`,
		deviceID).Scan(&publicKey)
	return publicKey, err
}

func (s *Store) CreateChallenge(ctx context.Context, id, deviceID string,
	nonce []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth_challenges (id, device_id, nonce, expires_at)
		VALUES ($1, $2, $3, $4)`, id, deviceID, nonce, expiresAt)
	return err
}

// ConsumeChallenge atomically marks a challenge used and returns its nonce.
func (s *Store) ConsumeChallenge(ctx context.Context, id, deviceID string) ([]byte, error) {
	var nonce []byte
	err := s.pool.QueryRow(ctx, `
		UPDATE auth_challenges
		SET used = true
		WHERE id = $1 AND device_id = $2 AND used = false AND expires_at > now()
		RETURNING nonce`, id, deviceID).Scan(&nonce)
	return nonce, err
}

func (s *Store) CreateGrant(ctx context.Context, id, deviceID, taskID string,
	wrappedKey []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO grants (id, device_id, task_id, wrapped_key, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		id, deviceID, taskID, wrappedKey, expiresAt)
	return err
}

func (s *Store) RevokeGrant(ctx context.Context, id string) error {
	command, err := s.pool.Exec(ctx,
		`UPDATE grants SET revoked = true WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) GetGrant(ctx context.Context, id string) (Grant, error) {
	var grant Grant
	err := s.pool.QueryRow(ctx, `
		SELECT id, device_id, task_id, wrapped_key, expires_at, revoked, created_at
		FROM grants WHERE id = $1`, id).Scan(&grant.ID, &grant.DeviceID,
		&grant.TaskID, &grant.WrappedKey, &grant.ExpiresAt, &grant.Revoked,
		&grant.CreatedAt)
	return grant, err
}
