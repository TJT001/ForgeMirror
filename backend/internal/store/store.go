package store

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Task struct {
	ID             string     `json:"id"`
	Status         string     `json:"status"`
	Profile        string     `json:"profile"`
	SigningMode    string     `json:"signing_mode"`
	SourcePath     string     `json:"source_path"`
	SourceSHA256   *string    `json:"source_sha256,omitempty"`
	PackageName    *string    `json:"package_name,omitempty"`
	VersionCode    *int64     `json:"version_code,omitempty"`
	Attempt        int        `json:"attempt"`
	MaxAttempts    int        `json:"max_attempts"`
	LeaseOwner     *string    `json:"lease_owner,omitempty"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	HeartbeatAt    *time.Time `json:"heartbeat_at,omitempty"`
	WorkDir        *string    `json:"work_dir,omitempty"`
	ResultPath     *string    `json:"result_path,omitempty"`
	ReasonCode     *string    `json:"reason_code,omitempty"`
	ErrorMessage   *string    `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Event struct {
	ID         int64     `json:"id"`
	TaskID     string    `json:"task_id"`
	Attempt    int       `json:"attempt"`
	Sequence   int       `json:"sequence"`
	Stage      *string   `json:"stage,omitempty"`
	Status     *string   `json:"status,omitempty"`
	Progress   *int      `json:"progress,omitempty"`
	ReasonCode *string   `json:"reason_code,omitempty"`
	Message    *string   `json:"message,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type NewEvent struct {
	Sequence   int     `json:"sequence"`
	Stage      *string `json:"stage"`
	Status     *string `json:"status"`
	Progress   *int    `json:"progress"`
	ReasonCode *string `json:"reason_code"`
	Message    *string `json:"message"`
}

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Migrate(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, string(body)); err != nil {
			return err
		}
	}
	return nil
}

const taskColumns = `id, status, profile, signing_mode, source_path, source_sha256,
	package_name, version_code, attempt, max_attempts, lease_owner, lease_expires_at,
	heartbeat_at, work_dir, result_path, reason_code, error_message, created_at, updated_at`

func scanTask(row pgx.Row) (Task, error) {
	var task Task
	err := row.Scan(&task.ID, &task.Status, &task.Profile, &task.SigningMode,
		&task.SourcePath, &task.SourceSHA256, &task.PackageName, &task.VersionCode,
		&task.Attempt, &task.MaxAttempts, &task.LeaseOwner, &task.LeaseExpiresAt,
		&task.HeartbeatAt, &task.WorkDir, &task.ResultPath, &task.ReasonCode,
		&task.ErrorMessage, &task.CreatedAt, &task.UpdatedAt)
	return task, err
}

func (s *Store) CreateTask(ctx context.Context, id, sourcePath, sha256,
	profile, signingMode string) (Task, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO tasks (id, source_path, source_sha256, profile, signing_mode)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+taskColumns,
		id, sourcePath, sha256, profile, signingMode)
	return scanTask(row)
}

func (s *Store) GetTask(ctx context.Context, id string) (Task, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = $1`, id)
	return scanTask(row)
}

func (s *Store) ListEvents(ctx context.Context, taskID string, afterID int64) ([]Event, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, task_id, attempt, sequence, stage, status, progress,
		       reason_code, message, created_at
		FROM task_events
		WHERE task_id = $1 AND id > $2
		ORDER BY id
		LIMIT 200`, taskID, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.TaskID, &event.Attempt, &event.Sequence,
			&event.Stage, &event.Status, &event.Progress, &event.ReasonCode,
			&event.Message, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) ClaimTask(ctx context.Context, workerID string, leaseSeconds int) (*Task, error) {
	row := s.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id FROM tasks
			WHERE status = 'queued'
			   OR (status = 'running' AND lease_expires_at < now())
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE tasks t
		SET status = 'running',
		    attempt = t.attempt + 1,
		    lease_owner = $1,
		    lease_expires_at = now() + make_interval(secs => $2),
		    heartbeat_at = now(),
		    updated_at = now()
		FROM candidate c
		WHERE t.id = c.id
		RETURNING `+taskColumns, workerID, leaseSeconds)
	task, err := scanTask(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *Store) Heartbeat(ctx context.Context, taskID, workerID string,
	leaseSeconds int) (bool, error) {
	var canceled bool
	err := s.pool.QueryRow(ctx, `
		UPDATE tasks
		SET lease_expires_at = now() + make_interval(secs => $3),
		    heartbeat_at = now(),
		    updated_at = now()
		WHERE id = $1 AND lease_owner = $2 AND status = 'running'
		RETURNING status = 'canceled'`, taskID, workerID, leaseSeconds).Scan(&canceled)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return canceled, err
}

func (s *Store) AddEvents(ctx context.Context, taskID string, attempt int,
	events []NewEvent) error {
	batch := &pgx.Batch{}
	for _, event := range events {
		batch.Queue(`
			INSERT INTO task_events
				(task_id, attempt, sequence, stage, status, progress, reason_code, message)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (task_id, attempt, sequence) DO NOTHING`,
			taskID, attempt, event.Sequence, event.Stage, event.Status,
			event.Progress, event.ReasonCode, event.Message)
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

func (s *Store) Complete(ctx context.Context, taskID, workerID string, success bool,
	resultPath, packageName *string, versionCode *int64,
	reasonCode, message *string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var attempt, maxAttempts int
	err = tx.QueryRow(ctx, `
		SELECT attempt, max_attempts FROM tasks
		WHERE id = $1 AND lease_owner = $2 AND status = 'running'
		FOR UPDATE`, taskID, workerID).Scan(&attempt, &maxAttempts)
	if err != nil {
		return err
	}

	if success {
		_, err = tx.Exec(ctx, `
			UPDATE tasks
			SET status = 'succeeded', result_path = $3, package_name = $4,
			    version_code = $5, reason_code = NULL, error_message = NULL,
			    lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
			WHERE id = $1 AND lease_owner = $2`,
			taskID, workerID, resultPath, packageName, versionCode)
		if err != nil {
			return err
		}
	} else if attempt < maxAttempts {
		_, err = tx.Exec(ctx, `
			UPDATE tasks
			SET status = 'queued', reason_code = $3, error_message = $4,
			    lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
			WHERE id = $1 AND lease_owner = $2`,
			taskID, workerID, reasonCode, message)
		if err != nil {
			return err
		}
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE tasks
			SET status = 'failed', reason_code = $3, error_message = $4,
			    lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
			WHERE id = $1 AND lease_owner = $2`,
			taskID, workerID, reasonCode, message)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) Cancel(ctx context.Context, taskID string) (Task, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE tasks
		SET status = 'canceled', updated_at = now()
		WHERE id = $1 AND status IN ('queued', 'running')
		RETURNING `+taskColumns, taskID)
	return scanTask(row)
}

func (s *Store) IsCanceled(ctx context.Context, taskID string) (bool, error) {
	var canceled bool
	err := s.pool.QueryRow(ctx,
		`SELECT status = 'canceled' FROM tasks WHERE id = $1`, taskID).Scan(&canceled)
	return canceled, err
}
