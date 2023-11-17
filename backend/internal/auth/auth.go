package auth

import (
	"fmt"
	"os"
	"strings"
	"thisweek/backend/internal/database"
	"thisweek/backend/internal/utils"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

const AccessTokenIssuer = "thisweek-access"
const RefreshTokenIssuer = "thisweek-refresh"

func mintToken(a *utils.DBConfig, id string, issuer string, expiresInSeconds int) (string, error) {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	claims := jwt.RegisteredClaims{}
	claims.Issuer = issuer
	claims.IssuedAt = jwt.NewNumericDate(time.Now().UTC())
	claims.ExpiresAt = jwt.NewNumericDate(claims.IssuedAt.Add(time.Second * time.Duration(expiresInSeconds)))
	claims.Subject = id
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func MintRefreshToken(a *utils.DBConfig, id string) (string, error) {
	tokenString, err := mintToken(a, id, RefreshTokenIssuer, 5184000)
	if err == nil {
		godotenv.Load()
		refreshObject := database.AddRefreshTokenParams{}
		refreshObject.IssuedAt = time.Now()
		refreshObject.ID = tokenString
		a.DB.AddRefreshToken(a.CTX, refreshObject)
	}
	return tokenString, err
}

func MintAccessToken(a *utils.DBConfig, id string) (string, error) {
	return mintToken(a, id, "thisweek-access", 86400)
}

func ValidateBearerToken(a *utils.DBConfig, bearerToken string) (database.User, error) {
	jwtToken := strings.Split(bearerToken, " ")[1]
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(jwtToken, &claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		return []byte(jwtSecret), nil
	})
	if err == nil && token.Valid && claims.Issuer == AccessTokenIssuer {
		if userId, perr := uuid.Parse(claims.Subject); perr != nil {
			return a.DB.GetUserById(a.CTX, userId)
		}
	}
	return database.User{}, fmt.Errorf("Invalid Token")
}
