package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func setupTestDB(t *testing.T) *sql.DB {
	// TODO: consider fixing reliance on hard coded database url
	connStr := "postgres://postgres:password123@localhost:5432/rts-demo?sslmode=disable"
	testDB, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	_, err = testDB.Exec(`
		DROP TABLE IF EXISTS users;
		CREATE TABLE users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create user table: %v", err)
	}

	return testDB
}

func setupTestApp(t *testing.T) *App {
	db := setupTestDB(t)
	store := sessions.NewCookieStore([]byte("test-key"))
	app := NewApp(db, store, initTemplate())
	return app
}

func TestSignupHandler(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create request
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "password123")

	req, err := http.NewRequest("POST", "/signup", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.signupHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	// Verify user was created in database
	var email string
	err = app.db.QueryRow("SELECT email FROM users WHERE email = $1", "test@example.com").Scan(&email)
	if err != nil {
		t.Errorf("User was not created in database: %v", err)
	}
	if email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", email)
	}
}

func TestLoginHandler(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create a test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := app.db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", "login@example.com", hashedPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create request
	form := url.Values{}
	form.Add("email", "login@example.com")
	form.Add("password", "password123")

	req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.loginHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	// Check redirect location
	location := rr.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected redirect to /dashboard, got %s", location)
	}
}

func TestAuthMiddlewareWithoutAuth(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create request
	req, err := http.NewRequest("GET", "/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create response
	rr := httptest.NewRecorder()
	handler := app.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler.ServeHTTP(rr, req)

	// Check does redirect
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Unauthenticated request should redirect: got %v want %v", status, http.StatusSeeOther)
	}
}

func TestAuthMiddlewareWithAuth(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Create response
	rec := httptest.NewRecorder()
	handler := app.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Create session
	session, err := app.store.Get(req, "auth-session")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	session.Values["authenticated"] = true
	session.Save(req, rec)
	cookie := rec.Result().Cookies()[0]
	req.AddCookie(cookie)

	handler.ServeHTTP(rec, req)

	// Check ok
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 OK, got %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "OK" {
		t.Errorf("expected body 'OK', got %q", rec.Body.String())
	}
}

func TestStockHandlerInvalidSymbol(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	// Create requst
	form := url.Values{}
	form.Add("symbol", "")

	req, err := http.NewRequest("POST", "/stock", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.stockHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "error") {
		t.Errorf("Expected error response for empty symbol")
	}
}

func TestDashboardRouteProtection(t *testing.T) {
	app := setupTestApp(t)
	defer app.db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/dashboard", app.authMiddleware(app.dashboardHandler)).Methods("GET")

	req, err := http.NewRequest("GET", "/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("Unprotected dashboard access should redirect: got %v want %v", status, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}
