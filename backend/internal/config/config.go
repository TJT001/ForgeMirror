package config

import "os"

type Config struct {
	Port            string
	DatabaseURL     string
	MigrationsDir   string
	DataDir         string
	WorkerToken     string
	MaxUploadBytes  int64
	LeaseSeconds    int
}

func Load() Config {
	return Config{
		Port:           env("PORT", "8080"),
		DatabaseURL:    env("DATABASE_URL", "postgres://forgemirror:forgemirror_dev@localhost:5432/forgemirror?sslmode=disable"),
		MigrationsDir:  env("MIGRATIONS_DIR", "migrations"),
		DataDir:        env("DATA_DIR", "data"),
		WorkerToken:    env("WORKER_TOKEN", "dev-worker-token"),
		MaxUploadBytes: 512 << 20,
		LeaseSeconds:   60,
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
