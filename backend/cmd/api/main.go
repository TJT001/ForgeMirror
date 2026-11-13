package main

import (
	"context"
	"log"
	"time"

	"forgemirror/backend/internal/api"
	"forgemirror/backend/internal/auth"
	"forgemirror/backend/internal/config"
	"forgemirror/backend/internal/store"
)

func main() {
	cfg := config.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(ctx, cfg.MigrationsDir); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	server := api.New(cfg, st, auth.New(st, cfg.DataDir,
		time.Duration(cfg.ChallengeTTLSec)*time.Second,
		time.Duration(cfg.GrantTTLSec)*time.Second))
	log.Printf("forgemirror api listening on :%s", cfg.Port)
	if err := server.Router().Run(":" + cfg.Port); err != nil {
		log.Fatalf("http: %v", err)
	}
}
