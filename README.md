# RTS Stock Lookup Application

A full-stack Go web application for real-time stock price lookups with secure user authentication. Built as a coding demonstration for Rising Tide Solutions.

## Features

- Secure Authentication - User registration and login with password hashing
- Database Integration - PostgreSQL for persistent user data storage
- Real-Time Stock Data - Live stock quotes from Finnhub API
- Modern UI - Responsive, gradient-themed interface with smooth animations
- Comprehensive Tests - Test coverage for authentication and core features

## Technology Stack

- Language: Go
- Routing: Gorilla Mux
- Database: PostgreSQL
- Session Management: Gorilla Session
- Password Security: bcrypt
- Financial API: Finnhub
- Front End: Go http templates, HTML, CSS, VanillaJS
- Containerization: Podman
- Deployment Railway

## Quick Start

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd rts-stock-app
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Set Up PostgreSQL

Create the required databases:

```bash
# Production database
createdb rts_stock_app

# Test database
createdb rts_stock_app_test
```

The application automatically creates the necessary tables on startup.

### 4. Configure Environment Variables

Export these variables:

```bash
export DATABASE_URL="postgres://<user>:<password>@<host>/rts-demo?sslmode=disable"
export FINNHUB_API_KEY="your_api_key_here"
export SESSION_KEY="your-secret-session-key"
export PORT="8080"
```

#### Getting a Finnhub API Key

1. Visit finnhub.io
2. Sign up for a free account
3. Copy your API key from the dashboard

#### Generating a Session Key

```bash
openssl rand -base64 32
```

### 5. Run the Application

```bash
go run .
```

Visit [http://localhost:8080] in your browser.

### 6. Run Tests

```bash
go test -v
```
