// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: auth.sql

package database

import (
	"context"
)

const addRefreshToken = `-- name: AddRefreshToken :one
INSERT INTO auth(id)
VALUES ($1)
RETURNING id
`

func (q *Queries) AddRefreshToken(ctx context.Context, id string) (string, error) {
	row := q.db.QueryRowContext(ctx, addRefreshToken, id)
	err := row.Scan(&id)
	return id, err
}

const getRefreshToken = `-- name: GetRefreshToken :one
SELECT id FROM auth WHERE id=$1
`

func (q *Queries) GetRefreshToken(ctx context.Context, id string) (string, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, id)
	err := row.Scan(&id)
	return id, err
}

const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
DELETE FROM auth WHERE id=$1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, id)
	return err
}