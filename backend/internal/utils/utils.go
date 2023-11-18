package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"thisweek/backend/internal/database"
	"context"
)


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
