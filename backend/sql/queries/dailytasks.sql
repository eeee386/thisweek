
-- name: AddDailyTask :one
INSERT INTO dailytasks(id, title, description, date_start, repetitions, user_id, tag_id, created_at, updated_at)
  VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
  RETURNING *;

-- name: GetDailyTasksByUserId :many
SELECT * FROM dailytasks WHERE user_id = $1;

-- name: UpdateDailyTask :one
  UPDATE dailytasks
  SET title = $2,
      description = $3,
      date_start = $4,
      repetitions = $5,
      user_id = $6,
      tag_id = $7,
      updated_at = $8
  WHERE id = $1
  RETURNING *;

-- name: DeleteDailyTask :exec
  DELETE FROM dailytasks * WHERE id = $1;
