-- name: CreateUser :one
  INSERT INTO users(id, created_at, updated_at, name, password)
  VALUES ($1, $2, $3, $4, $5)
  RETURNING *;

-- name: GetUserById :one
  SELECT * FROM users WHERE user_id = $1;

-- name: GetUserByNameAndPassword :one
  SELECT * FROM users WHERE name=$1 AND password=$2;
