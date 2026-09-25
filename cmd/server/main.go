// Command server runs the protobuf compatibility registry.
//
// Environment:
//
//	DATABASE_URL  PostgreSQL DSN (required), e.g. postgres://user:pass@host:5432/registry
//	ADDR          listen address (default :8080)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"protocompat/internal/service"
	"protocompat/internal/store"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	svc := service.New(store.NewPostgres(pool))
	log.Printf("registry listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, service.NewHandler(svc)))
}
