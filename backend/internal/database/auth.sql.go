// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: auth.sql

package database

import (
	"context"
	"time"
)

const addRefreshToken = `-- name: AddRefreshToken :one
INSERT INTO auth(id, issued_at)
VALUES ($1, $2)
RETURNING id, issued_at
`

type AddRefreshTokenParams struct {
	ID       string    `json:"id"`
	IssuedAt time.Time `json:"issued_at"`
}

func (q *Queries) AddRefreshToken(ctx context.Context, arg AddRefreshTokenParams) (Auth, error) {
	row := q.db.QueryRowContext(ctx, addRefreshToken, arg.ID, arg.IssuedAt)
	var i Auth
	err := row.Scan(&i.ID, &i.IssuedAt)
	return i, err
}

const getRefreshToken = `-- name: GetRefreshToken :one
SELECT id, issued_at FROM auth WHERE id=$1
`

func (q *Queries) GetRefreshToken(ctx context.Context, id string) (Auth, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, id)
	var i Auth
	err := row.Scan(&i.ID, &i.IssuedAt)
	return i, err
}

const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
DELETE FROM auth WHERE id=$1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, id)
	return err
}
