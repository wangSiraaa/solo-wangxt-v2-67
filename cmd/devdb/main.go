// Command devdb starts a throwaway embedded PostgreSQL and runs the registry
// server against it. It exists for local development and end-to-end checks
// on machines without a system PostgreSQL.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"

	"protocompat/internal/service"
	"protocompat/internal/store"
)

func main() {
	pg := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Port(15432).
			Database("registry"),
	)
	if err := pg.Start(); err != nil {
		log.Fatalf("start embedded postgres: %v", err)
	}
	defer func() {
		if err := pg.Stop(); err != nil {
			log.Printf("stop postgres: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, "postgres://postgres:postgres@localhost:15432/registry?sslmode=disable")
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	svc := service.New(store.NewPostgres(pool))
	log.Print("registry listening on :8080 (embedded postgres on :15432)")
	log.Fatal(http.ListenAndServe(":8080", service.NewHandler(svc)))
}
