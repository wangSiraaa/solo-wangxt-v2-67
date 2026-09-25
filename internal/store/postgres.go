package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the production Store backed by PostgreSQL.
type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

// Migrate creates the schema if it does not exist yet.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS packages (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS versions (
    id             BIGSERIAL PRIMARY KEY,
    package_id     BIGINT NOT NULL REFERENCES packages(id),
    version        TEXT NOT NULL,
    content_hash   TEXT NOT NULL,
    owned_files    JSONB NOT NULL,
    descriptor_set BYTEA NOT NULL,
    report         JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (package_id, version)
);
CREATE TABLE IF NOT EXISTS consumers (
    id         BIGSERIAL PRIMARY KEY,
    package_id BIGINT NOT NULL REFERENCES packages(id),
    name       TEXT NOT NULL,
    fields     JSONB NOT NULL,
    encodings  TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (package_id, name)
);`)
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (p *Postgres) EnsurePackage(ctx context.Context, name string) (*Package, error) {
	var pkg Package
	err := p.pool.QueryRow(ctx, `
INSERT INTO packages (name) VALUES ($1)
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
RETURNING id, name, created_at`, name).Scan(&pkg.ID, &pkg.Name, &pkg.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("ensure package: %w", err)
	}
	return &pkg, nil
}

func (p *Postgres) GetPackage(ctx context.Context, name string) (*Package, error) {
	var pkg Package
	err := p.pool.QueryRow(ctx,
		`SELECT id, name, created_at FROM packages WHERE name = $1`, name).
		Scan(&pkg.ID, &pkg.Name, &pkg.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &pkg, nil
}

const versionColumns = `id, package_id, version, content_hash, owned_files, descriptor_set, report, created_at`

func scanVersion(row pgx.Row) (*Version, error) {
	var v Version
	var owned []byte
	err := row.Scan(&v.ID, &v.PackageID, &v.Version, &v.ContentHash, &owned, &v.DescriptorSet, &v.Report, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(owned, &v.OwnedFiles); err != nil {
		return nil, fmt.Errorf("decode owned files: %w", err)
	}
	return &v, nil
}

func (p *Postgres) GetVersion(ctx context.Context, packageID int64, version string) (*Version, error) {
	return scanVersion(p.pool.QueryRow(ctx,
		`SELECT `+versionColumns+` FROM versions WHERE package_id = $1 AND version = $2`,
		packageID, version))
}

func (p *Postgres) LatestVersion(ctx context.Context, packageID int64) (*Version, error) {
	return scanVersion(p.pool.QueryRow(ctx,
		`SELECT `+versionColumns+` FROM versions WHERE package_id = $1 ORDER BY id DESC LIMIT 1`,
		packageID))
}

func (p *Postgres) InsertVersion(ctx context.Context, v *Version) error {
	owned, err := json.Marshal(v.OwnedFiles)
	if err != nil {
		return err
	}
	err = p.pool.QueryRow(ctx, `
INSERT INTO versions (package_id, version, content_hash, owned_files, descriptor_set, report)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, created_at`,
		v.PackageID, v.Version, v.ContentHash, owned, v.DescriptorSet, v.Report).
		Scan(&v.ID, &v.CreatedAt)
	if isUniqueViolation(err) {
		return ErrVersionConflict
	}
	return err
}

func (p *Postgres) UpsertConsumer(ctx context.Context, c *Consumer) error {
	fields, err := json.Marshal(c.Fields)
	if err != nil {
		return err
	}
	return p.pool.QueryRow(ctx, `
INSERT INTO consumers (package_id, name, fields, encodings)
VALUES ($1, $2, $3, $4)
ON CONFLICT (package_id, name) DO UPDATE SET fields = EXCLUDED.fields, encodings = EXCLUDED.encodings
RETURNING id, created_at`,
		c.PackageID, c.Name, fields, c.Encodings).Scan(&c.ID, &c.CreatedAt)
}

func (p *Postgres) ListConsumers(ctx context.Context, packageID int64) ([]*Consumer, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, package_id, name, fields, encodings, created_at FROM consumers WHERE package_id = $1 ORDER BY name`,
		packageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Consumer
	for rows.Next() {
		var c Consumer
		var fields []byte
		if err := rows.Scan(&c.ID, &c.PackageID, &c.Name, &fields, &c.Encodings, &c.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(fields, &c.Fields); err != nil {
			return nil, fmt.Errorf("decode consumer fields: %w", err)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}
