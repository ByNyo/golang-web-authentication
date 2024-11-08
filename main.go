package main

import (
	"golang-authentication/pkg/database"
	"golang-authentication/pkg/model"
	"golang-authentication/pkg/server"
	"log"
	"net/http"
)

func main() {
	db := database.NewDatabase(make(map[string]*model.User))
	_, err := db.AddUser("Test", "1234", "test@mail.de")
	if err != nil {
		log.Fatal(err)
		return
	}
	s, mux := server.NewServer(db)
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", s.Home)
	mux.HandleFunc("/login", s.Login)
	mux.HandleFunc("/register", s.Register)
	mux.HandleFunc("/profile/", s.Profile)
	mux.HandleFunc("/validate", s.Validate)
	mux.HandleFunc("/settings", s.Settings)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		return
	}
}
