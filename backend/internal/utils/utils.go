package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"thisweek/backend/internal/database"
	"time"
)

const BaseDateString = "1990-02-12"

type DBConfig struct {
	DB  *database.Queries
	CTX context.Context
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func RespondWithError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	respBody := ErrorResponse{
		Error: msg,
	}
	w.WriteHeader(code)
	dat, err := json.Marshal(respBody)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	} else {
		w.Write(dat)
	}
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	} else {
		w.WriteHeader(code)
		w.Write(dat)
	}
}

type TagRequestType struct {
	Name string `json:"name"`
}

func (req *TagRequestType) ToRenameTag(id string, userId uuid.UUID) (database.RenameTagParams, error) {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return database.RenameTagParams{}, err

	} else {
		return database.RenameTagParams{
			ID:        uuid,
			Name:      req.Name,
			UpdatedAt: time.Now(),
			UserID:    userId,
		}, nil
	}
}

func (req *TagRequestType) ToCreateTag(userId uuid.UUID) database.AddTagParams {
	timeStamp := time.Now()
	return database.AddTagParams{
		ID:        uuid.New(),
		Name:      req.Name,
		UserID:    userId,
		CreatedAt: timeStamp,
		UpdatedAt: timeStamp,
	}
}

type TaskRequestType struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	EventStart  string `json:"event_start"`
	EventEnd    string `json:"event_end"`
	Repetitions string `json:"repetitions"`
	TagID       string `json:"tag_id"`
}

func (req *TaskRequestType) ToUpdateTask(idstring string, userId uuid.UUID) (database.UpdateTaskParams, error) {
	id, err := uuid.Parse(idstring)
	if err != nil {
		return database.UpdateTaskParams{}, fmt.Errorf("Invalid id")
	}
	eventStartTime, eserr := time.Parse(BaseDateString, req.EventStart)
	if eserr != nil {
		return database.UpdateTaskParams{}, fmt.Errorf("Event start is not a valid date!")
	}
	eventEndTime, eeerr := time.Parse(BaseDateString, req.EventEnd)
	if eeerr != nil {
		return database.UpdateTaskParams{}, fmt.Errorf("Event end is not a valid date!")
	}
	tagId, err := uuid.Parse(req.TagID)
	if err != nil {
		return database.UpdateTaskParams{}, fmt.Errorf("Invalid Tag ID")
	}
	return database.UpdateTaskParams{
		ID:          id,
		UserID:      userId,
		Title:       req.Title,
		EventStart:  eventStartTime,
		EventEnd:    eventEndTime,
		UpdatedAt:   time.Now(),
		Repetitions: req.Repetitions,
		TagID:       tagId,
	}, nil
}

func (req *TaskRequestType) ToCreateTask(userId uuid.UUID) (database.AddTaskParams, error) {
	eventStartTime, eserr := time.Parse(BaseDateString, req.EventStart)
	if eserr != nil {
		return database.AddTaskParams{}, fmt.Errorf("Event start is not a valid date!")
	}
	eventEndTime, eeerr := time.Parse(BaseDateString, req.EventEnd)
	if eeerr != nil {
		return database.AddTaskParams{}, fmt.Errorf("Event end is not a valid date!")
	}
	tagId, err := uuid.Parse(req.TagID)
	if err != nil {
		return database.AddTaskParams{}, fmt.Errorf("Invalid tag id")
	}
	timeStamp := time.Now()
	return database.AddTaskParams{
		ID:          uuid.New(),
		UserID:      userId,
		Title:       req.Title,
		EventStart:  eventStartTime,
		EventEnd:    eventEndTime,
		UpdatedAt:   timeStamp,
		CreatedAt:   timeStamp,
		Repetitions: req.Repetitions,
		TagID:       tagId,
	}, nil

}

type DailyTaskRequestType struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	DateStart   string `json:"event_start"`
	Repetitions string `json:"repetitions"`
	TagID       string `json:"tag_id"`
}

func (req *DailyTaskRequestType) ToUpdateDailyTask(idstring string, userId uuid.UUID) (database.UpdateDailyTaskParams, error) {
	id, err := uuid.Parse(idstring)
	if err != nil {
		return database.UpdateDailyTaskParams{}, fmt.Errorf("Invalid id")
	}
	dateStartTime, eserr := time.Parse(BaseDateString, req.DateStart)
	if eserr != nil {
		return database.UpdateDailyTaskParams{}, fmt.Errorf("Date start is not a valid date!")
	}
	tagId, err := uuid.Parse(req.TagID)
	if err != nil {
		return database.UpdateDailyTaskParams{}, fmt.Errorf("Invalid Tag ID")
	}
	return database.UpdateDailyTaskParams{
		ID:          id,
		UserID:      userId,
		Title:       req.Title,
		DateStart:   dateStartTime,
		UpdatedAt:   time.Now(),
		Repetitions: req.Repetitions,
		TagID:       tagId,
	}, nil
}

func (req *DailyTaskRequestType) ToCreateDailyTask(userId uuid.UUID) (database.AddDailyTaskParams, error) {
	dateStartTime, eserr := time.Parse(BaseDateString, req.DateStart)
	if eserr != nil {
		return database.AddDailyTaskParams{}, fmt.Errorf("Event start is not a valid date!")
	}
	tagId, err := uuid.Parse(req.TagID)
	if err != nil {
		return database.AddDailyTaskParams{}, fmt.Errorf("Invalid Tag ID")
	}
	timeStamp := time.Now()
	return database.AddDailyTaskParams{
		ID:          uuid.New(),
		UserID:      userId,
		Title:       req.Title,
		DateStart:   dateStartTime,
		UpdatedAt:   timeStamp,
		CreatedAt:   timeStamp,
		Repetitions: req.Repetitions,
		TagID:       tagId,
	}, nil
}
