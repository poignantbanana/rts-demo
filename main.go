package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Email    string
	Password string
}

// docker exec -ti go-postgres-demo createdb -U postgres postgres-demo
type StockQuote struct {
	Symbol  string  `json:"symbol"`
	Open    float64 `json:"o"`
	High    float64 `json:"h"`
	Low     float64 `json:"l"`
	Current float64 `json:"c"`
}

type App struct {
	router *mux.Router
	db     *sql.DB
	store  *sessions.CookieStore
	tmpl   *template.Template
}

func New(db *sql.DB, store *sessions.CookieStore, tmpl *template.Template) *App {
	router := mux.NewRouter()

	app := &App{
		router: router,
		db:     db,
		store:  store,
		tmpl:   tmpl,
	}

	app.Routes()

	return app
}

func (app *App) Routes() {
	app.router.HandleFunc("/", app.homeHandler).Methods("GET")
	app.router.HandleFunc("/signup", app.signupPageHandler).Methods("GET")
	app.router.HandleFunc("/signup", app.signupHandler).Methods("POST")
	app.router.HandleFunc("/login", app.loginPageHandler).Methods("GET")
	app.router.HandleFunc("/login", app.loginHandler).Methods("POST")
	app.router.HandleFunc("/logout", app.logoutHandler).Methods("GET")

	app.router.HandleFunc("/dashboard", app.authMiddleware(app.dashboardHandler)).Methods("GET")
	app.router.HandleFunc("/stock", app.authMiddleware(app.stockHandler)).Methods("POST")

	app.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}

func (app *App) Run() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	return http.ListenAndServe(":"+port, app.router)
}

func initTemplate() *template.Template {
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
		log.Fatal("Missing environment variable DB_URL")
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

func main() {
	db := initDB()
	defer db.Close()

	app := New(db, initStore(), initTemplate())

	log.Fatal(app.Run())
}

func (app *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := app.store.Get(r, "auth-session")
		if err != nil {
			log.Fatal(err)
		}
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (app *App) homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.store.Get(r, "auth-session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	app.tmpl.ExecuteTemplate(w, "signup.html", nil)
}

func (app *App) signupPageHandler(w http.ResponseWriter, r *http.Request) {
	app.tmpl.ExecuteTemplate(w, "signup.html", nil)
}

func (app *App) signupHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		app.tmpl.ExecuteTemplate(w, "signup.html", map[string]string{
			"Error": "Email and password are required",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	_, err = app.db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", email, hashedPassword)
	if err != nil {
		app.tmpl.ExecuteTemplate(w, "signup.html", map[string]string{
			"Error": "Email already exists",
		})
		return
	}

	http.Redirect(w, r, "/login?registered=true", http.StatusSeeOther)
}

func (app *App) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{}
	if r.URL.Query().Get("registered") == "true" {
		data["Success"] = "Registartions successful! Please log in."
	}
	app.tmpl.ExecuteTemplate(w, "login.html", data)
}

func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	err := app.db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		println("Bad email:", err.Error())
		app.tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid email or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		println("Bad password: ", err.Error())
		app.tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid email or password"})
		return
	}

	session, _ := app.store.Get(r, "auth-session")
	session.Values["authenticated"] = true
	session.Values["email"] = user.Email
	session.Save(r, w)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.store.Get(r, "auth-session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.store.Get(r, "auth-session")
	email := session.Values["email"].(string)

	app.tmpl.ExecuteTemplate(w, "dashboard.html", map[string]string{
		"Email": email,
	})
}

func (app *App) stockHandler(w http.ResponseWriter, r *http.Request) {
	symbol := r.FormValue("symbol")
	if symbol == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Stock symbol is required",
		})
		return
	}

	apiKey := os.Getenv("FINNHUB_API_KEY")
	if apiKey == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"error": "API key not configured",
		})
		return
	}

	url := fmt.Sprintf("https://finnhub.io/api/v1/quote?symbol=%s&token=%s", symbol, apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to fetch stock data: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	var quote StockQuote
	if err := json.NewDecoder(resp.Body).Decode(&quote); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to parse stock data",
		})
		return
	}

	quote.Symbol = symbol

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(quote)
}
