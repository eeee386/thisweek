package main

import (
	"fmt"
	"database/sql"
	"os"
	"net/http"
	"context"
	"strings"
	"thisweek/backend/internal/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithJSON(w, 200, struct {
		Status string `json:"status"`
	}{Status: "OK"})
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	utils.RespondWithError(w, 500, "Internal Server Error")
}

type apiConfig struct {
	DB  *database.Queries
	ctx context.Context
}

type authedHandler func(http.ResponseWriter, *http.Request, database.User)

func (a *apiConfig) authenticate(handler authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		apikey := strings.Split(bearerToken, " ")[1]
		user, err := a.DB.GetUserByApiKey(a.ctx, apikey)
		if err != nil {
			utils.RespondWithError(w, 401, "Unauthorized")
		} else {
			handler(w, r, user)
		}
	}
}

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")

	dbURL := os.Getenv("CONN")
	db, derr := sql.Open("postgres", dbURL)
	if derr != nil {
		fmt.Println(derr.Error())
		return
	}

	dbQueries := database.New(db)
	apiCfg := apiConfig{}
	apiCfg.DB = dbQueries
	apiCfg.ctx = context.Background()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET, POST, OPTIONS, PUT, DELETE"},
		AllowedHeaders: []string{"*"},
	}))

	v1Router := chi.NewRouter()
	r.Mount("/v1", v1Router)

	v1Router.Get("/readiness", readinessHandler)
	v1Router.Get("/err", errorHandler)

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	fmt.Println(err)
}
