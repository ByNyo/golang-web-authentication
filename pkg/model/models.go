package model

import "github.com/golang-jwt/jwt"

type User struct {
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	EMail     string `json:"email"`
	ShowEMail bool   `json:"show_email"`
}

type Claims struct {
	User       User
	Authorized bool `json:"authorized"`
	jwt.StandardClaims
}
