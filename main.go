package main

import (
	"database/sql"
	"html/template"
	"log"
	"os"

	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

func main() {
	db := initDB()
	defer db.Close()

	app := NewApp(db, initStore(), initTemplates())

	log.Fatal(app.Run())
}

func initTemplates() *template.Template {
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Error parsing templates: ", err)
	}
	return tmpl
}

func initStore() *sessions.CookieStore {
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "test-key"
	}
	return sessions.NewCookieStore([]byte(sessionKey))
}

func initDB() *sql.DB {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("Missing environment variable DATABASE_URL")
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Error pinging database: ", err)
	}

	createUsersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createUsersTableSQL)
	if err != nil {
		log.Fatal("Error creating table:", err)
	}

	log.Println("Database initialized successfully")

	return db
}
