// Package store persists packages, immutable versions and consumer
// declarations. PostgreSQL is the production backend; an in-memory backend
// serves tests and the regression CLI.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Package is a named bundle of .proto files published together.
type Package struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// OwnedFile records which files of a version belong to the package itself
// (as opposed to imported dependency files).
type OwnedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Version is one immutable published version of a package.
type Version struct {
	ID            int64           `json:"id"`
	PackageID     int64           `json:"package_id"`
	Version       string          `json:"version"`
	ContentHash   string          `json:"content_hash"`
	OwnedFiles    []OwnedFile     `json:"owned_files"`
	DescriptorSet []byte          `json:"-"` // serialized FileDescriptorSet, self-contained
	Report        json.RawMessage `json:"report"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Consumer declares what a downstream user of a package relies on.
type Consumer struct {
	ID        int64     `json:"id"`
	PackageID int64     `json:"package_id"`
	Name      string    `json:"name"`
	Fields    []string  `json:"fields"`
	Encodings []string  `json:"encodings"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	// ErrNotFound is returned when the requested row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrVersionConflict is returned when inserting a version that already
	// exists; the service compares content hashes to distinguish idempotent
	// re-publish from a forbidden overwrite.
	ErrVersionConflict = errors.New("store: version already exists")
)

// Store is the persistence contract used by the registry service.
type Store interface {
	EnsurePackage(ctx context.Context, name string) (*Package, error)
	GetPackage(ctx context.Context, name string) (*Package, error)

	GetVersion(ctx context.Context, packageID int64, version string) (*Version, error)
	LatestVersion(ctx context.Context, packageID int64) (*Version, error)
	// InsertVersion stores a new version. It returns ErrVersionConflict if
	// the (package, version) pair already exists; existing rows are never
	// modified.
	InsertVersion(ctx context.Context, v *Version) error

	UpsertConsumer(ctx context.Context, c *Consumer) error
	ListConsumers(ctx context.Context, packageID int64) ([]*Consumer, error)
}
