package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

type Database struct {
	Users map[string]*User
}

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

var db *Database

func main() {
	db = &Database{Users: make(map[string]*User)}
	uid, err := GenerateUUID()
	if err != nil {
		panic(err)
	}
	db.Users[uid] = &User{
		UUID:      uid,
		Username:  "Admin",
		Password:  "admin",
		EMail:     "admin@mail.com",
		ShowEMail: false,
	}
	uid, err = GenerateUUID()
	if err != nil {
		panic(err)
	}
	db.Users[uid] = &User{
		UUID:      uid,
		Username:  "Test",
		Password:  "1234",
		EMail:     "test@testmail.com",
		ShowEMail: true,
	}
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/profile/", Profile)
	http.HandleFunc("/validate", Validate)
	http.HandleFunc("/settings", Settings)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		return
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("GAUTH-JWT")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			err = renderTemplate(w, "index.html", Claims{Authorized: false})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if cookie.Value != "" {
		claims := GetClaims(w, cookie.Value)
		err = renderTemplate(w, "index.html", claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func Profile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	path = strings.Replace(path, "/profile/@", "", 1)
	cookie, err := r.Cookie("GAUTH-JWT")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			user, err := GetSaveUser(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			claims := Claims{
				User:           user,
				Authorized:     false,
				StandardClaims: jwt.StandardClaims{},
			}
			after := time.Now().Add(time.Hour * 24).Unix()
			claims.ExpiresAt = after
			claims.IssuedAt = after
			err = renderTemplate(w, "profile.html", claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if cookie.Value != "" {
		claims := GetClaims(w, cookie.Value)
		if claims.Authorized == true {
			if claims.User.Username != path {
				user, err := GetSaveUser(path)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				claims := Claims{
					User:           user,
					Authorized:     false,
					StandardClaims: jwt.StandardClaims{},
				}
				after := time.Now().Add(time.Hour * 24).Unix()
				claims.ExpiresAt = after
				claims.IssuedAt = after
				err = renderTemplate(w, "profile.html", claims)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				return
			}
			err = renderTemplate(w, "profile.html", claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := renderTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		username := r.URL.Query().Get("username")
		password := r.URL.Query().Get("password")
		valid := ValidateUsername(username)
		if !valid {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		now := time.Now()
		user, err := GetUserByUsername(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if password != user.Password {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims := Claims{
			User:       *user,
			Authorized: true,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: now.Add(24 * time.Hour).Unix(),
				Id:        "",
				IssuedAt:  now.Unix(),
			},
		}
		tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tkn.Valid = true
		tkn.Header["typ"] = "Bearer TOKEN"
		tokenString, err := tkn.SignedString([]byte("secret"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cookie := http.Cookie{
			Name:     "GAUTH-JWT",
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Value:    tokenString,
			Expires:  now.Add(24 * time.Hour),
		}
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := renderTemplate(w, "register.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case http.MethodPost:
		var user User
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(data, &user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = AddUser(user.Username, user.Password, user.EMail)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func Settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cookie, err := r.Cookie("GAUTH-JWT")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if cookie.Value == "" {
			http.Error(w, http.ErrNoCookie.Error(), http.StatusUnauthorized)
			return
		}
		claims := GetClaims(w, cookie.Value)
		err = renderTemplate(w, "settings.html", claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		var user User
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(data, &user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		newUser, err := UpdateUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cookie, err := r.Cookie("GAUTH-JWT")
		if err != nil {
			return
		}
		claims := GetClaims(w, cookie.Value)
		claims = &Claims{
			User:       *newUser,
			Authorized: true,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: claims.ExpiresAt,
				Id:        "",
				IssuedAt:  claims.IssuedAt,
			},
		}
		tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tkn.Valid = true
		tkn.Header["typ"] = "Bearer TOKEN"
		tokenString, err := tkn.SignedString([]byte("secret"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cookie = &http.Cookie{
			Name:     "GAUTH-JWT",
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Value:    tokenString,
			Expires:  time.Unix(claims.ExpiresAt, 0),
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func Validate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		claims := GetClaims(w, string(body))
		exists := ContainsUser(claims.User.UUID)
		if !exists {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		data, err := json.Marshal(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
}

func ValidateUsername(username string) bool {
	if strings.Contains(username, "%00") {
		return false
	}
	return true
}

func GetClaims(writer http.ResponseWriter, tokenString string) *Claims {
	tkn, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			http.Error(writer, "Couldn't get cookie", http.StatusUnauthorized)
			return &Claims{}
		}
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return &Claims{}
	}
	return tkn.Claims.(*Claims)
}

func GetSaveUser(username string) (User, error) {
	var uid string
	for i, user := range db.Users {
		if user.Username == username {
			uid = i
		}
	}
	u, exists := db.Users[uid]
	if !exists {
		return User{}, fmt.Errorf("user not found")
	}
	if u == nil {
		return User{}, fmt.Errorf("empty user")
	}
	secureUser := User{
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

func GetUserByUsername(username string) (*User, error) {
	var uid string
	for i, user := range db.Users {
		if user.Username == username {
			uid = i
		}
	}
	user, exists := db.Users[uid]
	if !exists {
		return &User{}, fmt.Errorf("user not found")
	}
	if user == nil {
		return &User{}, fmt.Errorf("empty user")
	}
	return user, nil
}

func AddUser(username, password, email string) (*User, error) {
	if ContainsUserByUsername(username) {
		return nil, fmt.Errorf("user already exists")
	}
	uid, err := GenerateUUID()
	if err != nil {
		return nil, err
	}
	user := User{
		UUID:      uid,
		Username:  username,
		Password:  password,
		EMail:     email,
		ShowEMail: false,
	}
	db.Users[user.UUID] = &user
	return &user, nil
}

func UpdateUser(user User) (*User, error) {
	u, exists := db.Users[user.UUID]
	if !exists {
		return &User{}, fmt.Errorf("user not found")
	}
	if u == nil {
		return &User{}, fmt.Errorf("empty user")
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
	user = User{
		UUID:      user.UUID,
		Username:  user.Username,
		Password:  user.Password,
		EMail:     user.EMail,
		ShowEMail: user.ShowEMail,
	}
	db.Users[user.UUID] = &user
	return &user, nil
}

func ContainsUser(uuid string) bool {
	if _, exists := db.Users[uuid]; exists {
		return true
	}
	return false
}

func ContainsUserByUsername(username string) bool {
	for _, u := range db.Users {
		if u.Username == username {
			return true
		}
	}
	return false
}

func GenerateUUID() (string, error) {
	uid, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}

func renderTemplate(writer http.ResponseWriter, file string, data any) error {
	tmpl, err := template.ParseFiles(fmt.Sprintf("templates/%s", file))
	if err != nil {
		return err
	}
	err = tmpl.Execute(writer, data)
	if err != nil {
		return err
	}
	return nil
}
