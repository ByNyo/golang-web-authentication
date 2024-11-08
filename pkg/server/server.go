package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"golang-authentication/pkg/database"
	"golang-authentication/pkg/model"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

type SI interface {
	Home(w http.ResponseWriter, r *http.Request)
	Profile(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	Register(w http.ResponseWriter, r *http.Request)
	Settings(w http.ResponseWriter, r *http.Request)
	Validate(w http.ResponseWriter, r *http.Request)
}

type Server struct {
	db database.DB
}

func NewServer(database database.DB) (SI, *http.ServeMux) {
	return &Server{database}, http.NewServeMux()
}

func (s *Server) Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("GAUTH-JWT")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			err = renderTemplate(w, "index.html", model.Claims{Authorized: false})
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
		claims := s.db.GetClaims(w, cookie.Value)
		err = renderTemplate(w, "index.html", claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) Profile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	path = strings.Replace(path, "/profile/@", "", 1)
	cookie, err := r.Cookie("GAUTH-JWT")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			user, err := s.db.GetSaveUser(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			claims := model.Claims{
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
		claims := s.db.GetClaims(w, cookie.Value)
		if claims.Authorized == true {
			if claims.User.Username != path {
				user, err := s.db.GetSaveUser(path)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				claims := model.Claims{
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

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := renderTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		var user *model.User
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
		password := user.Password
		valid := s.db.ValidateUsername(user.Username)
		if !valid {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		now := time.Now()
		user, err = s.db.GetUserByUsername(user.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if password != user.Password {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims := model.Claims{
			User:       *user,
			Authorized: true,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: now.Add(24 * time.Hour).Unix(),
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

func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := renderTemplate(w, "register.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case http.MethodPost:
		var user model.User
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
		_, err = s.db.AddUser(user.Username, user.Password, user.EMail)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func (s *Server) Settings(w http.ResponseWriter, r *http.Request) {
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
		claims := s.db.GetClaims(w, cookie.Value)
		err = renderTemplate(w, "settings.html", claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		var user model.User
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
		newUser, err := s.db.UpdateUser(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cookie, err := r.Cookie("GAUTH-JWT")
		if err != nil {
			return
		}
		claims := s.db.GetClaims(w, cookie.Value)
		claims = &model.Claims{
			User:       *newUser,
			Authorized: true,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: claims.ExpiresAt,
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

func (s *Server) Validate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		claims := s.db.GetClaims(w, string(body))
		exists := s.db.ContainsUser(claims.User.UUID)
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
