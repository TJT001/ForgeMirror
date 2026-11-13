package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type NewSecurityEvent struct {
	Kind         string          `json:"kind"`
	RuleID       *string         `json:"rule_id"`
	Confidence   float64         `json:"confidence"`
	EvidenceHash *string         `json:"evidence_hash"`
	Payload      json.RawMessage `json:"payload"`
}

type SecurityEvent struct {
	ID           int64           `json:"id"`
	AppPackage   string          `json:"app_package"`
	DeviceID     *string         `json:"device_id,omitempty"`
	Kind         string          `json:"kind"`
	RuleID       *string         `json:"rule_id,omitempty"`
	Confidence   float64         `json:"confidence"`
	EvidenceHash *string         `json:"evidence_hash,omitempty"`
	Payload      json.RawMessage `json:"payload"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (s *Store) AddSecurityEvents(ctx context.Context, appPackage string,
	deviceID *string, events []NewSecurityEvent) error {
	batch := &pgx.Batch{}
	for _, event := range events {
		payload := event.Payload
		if len(payload) == 0 {
			payload = json.RawMessage(`{}`)
		}
		batch.Queue(`
			INSERT INTO security_events
				(app_package, device_id, kind, rule_id, confidence, evidence_hash, payload)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
			appPackage, deviceID, event.Kind, event.RuleID, event.Confidence,
			event.EvidenceHash, payload)
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

func (s *Store) ListSecurityEvents(ctx context.Context, limit int, kind, appPackage string) ([]SecurityEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, app_package, device_id, kind, rule_id, confidence,
		       evidence_hash, payload, created_at
		FROM security_events
		WHERE ($2 = '' OR kind = $2)
		  AND ($3 = '' OR app_package = $3)
		ORDER BY id DESC
		LIMIT $1`, limit, kind, appPackage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]SecurityEvent, 0)
	for rows.Next() {
		var event SecurityEvent
		if err := rows.Scan(&event.ID, &event.AppPackage, &event.DeviceID,
			&event.Kind, &event.RuleID, &event.Confidence, &event.EvidenceHash,
			&event.Payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
