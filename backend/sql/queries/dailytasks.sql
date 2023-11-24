
-- name: AddDailyTask :one
INSERT INTO dailytasks(id, title, description, date_start, repetitions, user_id, tag_id, created_at, updated_at)
  VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
  RETURNING *;

-- name: GetDailyTasksByUserId :many
SELECT * FROM dailytasks WHERE user_id = $1;

-- name: UpdateDailyTask :one
  UPDATE dailytasks
  SET title = $3,
      description = $4,
      date_start = $5,
      repetitions = $6,
      user_id = $7,
      tag_id = $8,
      updated_at = $9
  WHERE id = $1 AND user_id =$2
  RETURNING *;

-- name: DeleteDailyTask :exec
  DELETE FROM dailytasks * WHERE id = $1 AND user_id = $2;
