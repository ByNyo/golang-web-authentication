package database

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"golang-authentication/pkg/model"
	"golang-authentication/pkg/utils"
	"net/http"
	"strings"
)

type DB interface {
	ValidateUsername(username string) bool
	GetClaims(writer http.ResponseWriter, tokenString string) *model.Claims
	GetSaveUser(username string) (model.User, error)
	GetUserByUsername(username string) (*model.User, error)
	AddUser(username, password, email string) (*model.User, error)
	UpdateUser(user model.User) (*model.User, error)
	ContainsUser(uuid string) bool
}

type Database struct {
	Users map[string]*model.User
}

func NewDatabase(users map[string]*model.User) DB {
	return &Database{users}
}

func (db *Database) ValidateUsername(username string) bool {
	if strings.Contains(username, "%00") {
		return false
	}
	return true
}

func (db *Database) GetClaims(writer http.ResponseWriter, tokenString string) *model.Claims {
	tkn, err := jwt.ParseWithClaims(tokenString, &model.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			http.Error(writer, "Couldn't get cookie", http.StatusUnauthorized)
			return &model.Claims{}
		}
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return &model.Claims{}
	}
	return tkn.Claims.(*model.Claims)
}

func (db *Database) GetSaveUser(username string) (model.User, error) {
	var uid string
	for i, user := range db.Users {
		if user.Username == username {
			uid = i
		}
	}
	u, exists := db.Users[uid]
	if !exists {
		return model.User{}, fmt.Errorf("user not found")
	}
	if u == nil {
		return model.User{}, fmt.Errorf("empty user")
	}
	secureUser := model.User{
		Username:  u.Username,
		Password:  "",
		EMail:     "",
		UUID:      uid,
		ShowEMail: u.ShowEMail,
	}
	if u.ShowEMail {
		secureUser.EMail = u.EMail
	}
	return secureUser, nil
}

func (db *Database) GetUserByUsername(username string) (*model.User, error) {
	var uid string
	for i, user := range db.Users {
		if user.Username == username {
			uid = i
		}
	}
	user, exists := db.Users[uid]
	if !exists {
		return &model.User{}, fmt.Errorf("user not found")
	}
	if user == nil {
		return &model.User{}, fmt.Errorf("empty user")
	}
	return user, nil
}

func (db *Database) AddUser(username, password, email string) (*model.User, error) {
	if db.ContainsUserByUsername(username) {
		return nil, fmt.Errorf("user already exists")
	}
	uid, err := utils.GenerateUUID()
	if err != nil {
		return nil, err
	}
	user := model.User{
		UUID:      uid,
		Username:  username,
		Password:  password,
		EMail:     email,
		ShowEMail: false,
	}
	db.Users[user.UUID] = &user
	return &user, nil
}

func (db *Database) UpdateUser(user model.User) (*model.User, error) {
	u, exists := db.Users[user.UUID]
	if !exists {
		return &model.User{}, fmt.Errorf("user not found")
	}
	if u == nil {
		return &model.User{}, fmt.Errorf("empty user")
	}
	if user.Username == "" {
		user.Username = u.Username
	}
	if user.Password == "" {
		user.Password = u.Password
	}
	if user.EMail == "" {
		user.EMail = u.EMail
	}
	user = model.User{
		UUID:      user.UUID,
		Username:  user.Username,
		Password:  user.Password,
		EMail:     user.EMail,
		ShowEMail: user.ShowEMail,
	}
	db.Users[user.UUID] = &user
	return &user, nil
}

func (db *Database) ContainsUser(uuid string) bool {
	if _, exists := db.Users[uuid]; exists {
		return true
	}
	return false
}

func (db *Database) ContainsUserByUsername(username string) bool {
	for _, u := range db.Users {
		if u.Username == username {
			return true
		}
	}
	return false
}
