-- name: AddRefreshToken :one
INSERT INTO auth(id, issued_at)
VALUES ($1, $2)
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM auth WHERE id=$1;

-- name: RevokeRefreshToken :exec
DELETE FROM auth WHERE id=$1;
