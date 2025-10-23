package auth

import "github.com/golang-jwt/jwt/v5"

type NotaryJWTClaims struct {
	Permissions []string
	Email       string
	jwt.RegisteredClaims
}

type localJWTClaims struct {
	Permissions []string `json:"permissions"`
	Email       string   `json:"email"`
	jwt.RegisteredClaims
}
