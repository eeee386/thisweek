// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0

package database

import (
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type RepetitionTypes string

const (
	RepetitionTypesDay   RepetitionTypes = "day"
	RepetitionTypesWeek  RepetitionTypes = "week"
	RepetitionTypesMonth RepetitionTypes = "month"
	RepetitionTypesYear  RepetitionTypes = "year"
)

func (e *RepetitionTypes) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = RepetitionTypes(s)
	case string:
		*e = RepetitionTypes(s)
	default:
		return fmt.Errorf("unsupported scan type for RepetitionTypes: %T", src)
	}
	return nil
}

type NullRepetitionTypes struct {
	RepetitionTypes RepetitionTypes
	Valid           bool // Valid is true if RepetitionTypes is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullRepetitionTypes) Scan(value interface{}) error {
	if value == nil {
		ns.RepetitionTypes, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.RepetitionTypes.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullRepetitionTypes) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.RepetitionTypes), nil
}

type Auth struct {
	ID       string    `json:"id"`
	IssuedAt time.Time `json:"issued_at"`
}

type Dailytask struct {
	ID          uuid.UUID   `json:"id"`
	Title       string      `json:"title"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Description string      `json:"description"`
	DateStart   time.Time   `json:"date_start"`
	Repetitions interface{} `json:"repetitions"`
	UserID      uuid.UUID   `json:"user_id"`
	TagID       uuid.UUID   `json:"tag_id"`
}

type Tag struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UserID    uuid.UUID `json:"user_id"`
}

type Task struct {
	ID          uuid.UUID   `json:"id"`
	Title       string      `json:"title"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Description string      `json:"description"`
	EventStart  time.Time   `json:"event_start"`
	EventEnd    time.Time   `json:"event_end"`
	Repetitions interface{} `json:"repetitions"`
	UserID      uuid.UUID   `json:"user_id"`
	TagID       uuid.UUID   `json:"tag_id"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
}
