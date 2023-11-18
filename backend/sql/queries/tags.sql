-- name: GetTagsByUserId :many
  SELECT * FROM tags WHERE user_id = $1;
  
-- name: AddTag :one
  INSERT INTO tags(id, name, user_id, created_at, updated_at)
  VALUES ($1, $2, $3, $4, $5)
  RETURNING *;

-- name: RenameTag :one
  UPDATE tags
   SET name = $2,
       created_at = $3
  WHERE id = $1
  RETURNING *;

-- name: DeleteTag :exec
  DELETE FROM tags WHERE id = $1;
  
