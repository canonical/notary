package auth

import "github.com/golang-jwt/jwt/v5"

type NotaryJWTClaims struct {
	Permissions []string
	Email       string
	RoleID      int `json:"role_id"`
	jwt.RegisteredClaims
}

type localJWTClaims struct {
	Permissions []string `json:"permissions"`
	Email       string   `json:"email"`
	RoleID      int      `json:"role_id"`
	jwt.RegisteredClaims
}
