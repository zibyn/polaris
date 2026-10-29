// Package blob is the blob store adapter (ADR 0020): bytes by key, knowing
// nothing of what they are for. Only the PG backend exists.
package blob

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// ErrNotFound is a key with no blob.
var ErrNotFound = errors.New("blob not found")

type Store interface {
	// Put writes b under key, replacing what was there.
	Put(ctx context.Context, key string, b []byte, contentType string) error
	// Get reads the blob under key, or ErrNotFound.
	Get(ctx context.Context, key string) (b []byte, contentType string, err error)
	// Delete removes the blob under key; a missing one is no error.
	Delete(ctx context.Context, key string) error
}

// PG keeps blobs in the blobs table. Built on a transaction's Queries, its
// writes commit or roll back with the caller's.
type PG struct{ q *sqlc.Queries }

var _ Store = PG{}

func NewPG(q *sqlc.Queries) PG { return PG{q} }

func (p PG) Put(ctx context.Context, key string, b []byte, contentType string) error {
	return p.q.PutBlob(ctx, sqlc.PutBlobParams{Key: key, ContentType: contentType, Bytes: b})
}

func (p PG) Get(ctx context.Context, key string) ([]byte, string, error) {
	r, err := p.q.GetBlob(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	return r.Bytes, r.ContentType, err
}

func (p PG) Delete(ctx context.Context, key string) error { return p.q.DeleteBlob(ctx, key) }
