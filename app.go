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
	"golang.org/x/crypto/bcrypt"
)

// App holds references in a slightly nicer way than globally stored refs.
type App struct {
	router *mux.Router
	db     *sql.DB
	store  *sessions.CookieStore
	tmpl   *template.Template
}

// NewApp works as a quick and easy dependency injection method / constructor to create a new App.
func NewApp(db *sql.DB, store *sessions.CookieStore, tmpl *template.Template) *App {
	app := &App{
		router: mux.NewRouter(),
		db:     db,
		store:  store,
		tmpl:   tmpl,
	}

	app.Routes()

	return app
}

// Routes keeps all methods consolidated for easy reference,
// might consider moving to a separate file if significantly more routes were added.
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

// Run runs the App as a http server
func (app *App) Run() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	return http.ListenAndServe(":"+port, app.router)
}

// authMiddleware verifies that a connection is authenticated via session storage.
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

// homeHandler redirects to the dashboard or signup page depending on authenticated status.
func (app *App) homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.store.Get(r, "auth-session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	app.tmpl.ExecuteTemplate(w, "signup.html", nil)
}

// signupPageHandler serves the signup page.
func (app *App) signupPageHandler(w http.ResponseWriter, r *http.Request) {
	app.tmpl.ExecuteTemplate(w, "signup.html", nil)
}

// signupHandler takes form values and creates a new user with a hashed password.
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

// loginPageHandler serves the login page.
func (app *App) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{}
	if r.URL.Query().Get("registered") == "true" {
		data["Success"] = "Registartions successful! Please log in."
	}
	app.tmpl.ExecuteTemplate(w, "login.html", data)
}

// loginHandler takes form data then compares email and hashed password against the database.
// The user is given and authenticated session upon successful login.
func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	err := app.db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
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

// logoutHandler removes authentication from the users session and redirects to home.
func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.store.Get(r, "auth-session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// dashboardHandler serves dashboard html.
func (app *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.store.Get(r, "auth-session")
	email := session.Values["email"].(string)

	app.tmpl.ExecuteTemplate(w, "dashboard.html", map[string]string{
		"Email": email,
	})
}

// stockHandler takes a symbol and makes a request to finnhub returning and stock data or error.
func (app *App) stockHandler(w http.ResponseWriter, r *http.Request) {
	symbol := r.FormValue("symbol")
	if symbol == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Stock symbol is required",
		})
		return
	}

	apiKey := os.Getenv("FINNHUB_API_KEY")
	if apiKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
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
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to fetch stock data: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	var quote StockQuote
	if err := json.NewDecoder(resp.Body).Decode(&quote); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to parse stock data",
		})
		return
	}

	quote.Symbol = symbol

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(quote)
}
