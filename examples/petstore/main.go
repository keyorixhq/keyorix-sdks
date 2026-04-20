// Keyorix Pet Store — example application
//
// Demonstrates fetching database credentials from Keyorix at startup.
// Zero hardcoded credentials — all secrets come from Keyorix.
//
// Run with:
//
//	docker compose up
//
// Or manually:
//
//	KEYORIX_SERVER=http://localhost:8080 \
//	KEYORIX_TOKEN=your-token \
//	DATABASE_URL=postgres://user:pass@localhost:5432/petstore \
//	go run main.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	keyorix "github.com/keyorixhq/keyorix-go"
	_ "github.com/lib/pq"
)

type Pet struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Species   string    `json:"species"`
	CreatedAt time.Time `json:"created_at"`
}

var db *sql.DB

func main() {
	ctx := context.Background()

	// ── 1. Connect to Keyorix and fetch DB credentials ──────────────────────
	server := os.Getenv("KEYORIX_SERVER")
	token := os.Getenv("KEYORIX_TOKEN")

	if server == "" {
		log.Fatal("KEYORIX_SERVER environment variable is required")
	}
	if token == "" {
		log.Fatal("KEYORIX_TOKEN environment variable is required")
	}

	log.Printf("🔐 Connecting to Keyorix at %s", server)
	client := keyorix.New(server, token)

	if err := client.Health(ctx); err != nil {
		log.Fatalf("Keyorix health check failed: %v", err)
	}
	log.Printf("✅ Keyorix connection OK")

	// Fetch DB password from Keyorix
	log.Printf("🔑 Fetching database credentials from Keyorix...")
	dbPassword, err := client.GetSecret(ctx, "petstore-db-password", "production")
	if err != nil {
		log.Fatalf("Failed to fetch DB password from Keyorix: %v", err)
	}
	log.Printf("✅ Database credentials retrieved")

	// ── 2. Connect to PostgreSQL using the secret ────────────────────────────
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "petstore")
	dbName := getEnv("DB_NAME", "petstore")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	log.Printf("🐘 Connecting to PostgreSQL at %s:%s/%s", dbHost, dbPort, dbName)
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Wait for DB to be ready
	for i := 0; i < 10; i++ {
		if err := db.PingContext(ctx); err == nil {
			break
		}
		log.Printf("⏳ Waiting for database... (%d/10)", i+1)
		time.Sleep(2 * time.Second)
	}
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("Database not ready: %v", err)
	}
	log.Printf("✅ Database connection OK")

	// ── 3. Create table if not exists ───────────────────────────────────────
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pets (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			species TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		)`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	// ── 4. Start HTTP server ─────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pets", listPets)
	mux.HandleFunc("POST /pets", createPet)
	mux.HandleFunc("GET /pets/{id}", getPet)
	mux.HandleFunc("DELETE /pets/{id}", deletePet)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	port := getEnv("PORT", "3001")
	log.Printf("🚀 Pet Store API listening on http://localhost:%s", port)
	log.Printf("   Try: curl http://localhost:%s/pets", port)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func listPets(w http.ResponseWriter, r *http.Request) {
	rows, err := db.QueryContext(r.Context(), `SELECT id, name, species, created_at FROM pets ORDER BY id`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	pets := []Pet{}
	for rows.Next() {
		var p Pet
		if err := rows.Scan(&p.ID, &p.Name, &p.Species, &p.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pets = append(pets, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pets)
}

func createPet(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name    string `json:"name"`
		Species string `json:"species"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if input.Name == "" || input.Species == "" {
		http.Error(w, "name and species are required", http.StatusBadRequest)
		return
	}

	var p Pet
	err := db.QueryRowContext(r.Context(),
		`INSERT INTO pets (name, species) VALUES ($1, $2) RETURNING id, name, species, created_at`,
		input.Name, input.Species,
	).Scan(&p.ID, &p.Name, &p.Species, &p.CreatedAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

func getPet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var p Pet
	err = db.QueryRowContext(r.Context(),
		`SELECT id, name, species, created_at FROM pets WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Species, &p.CreatedAt)
	if err == sql.ErrNoRows {
		http.Error(w, "pet not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func deletePet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	result, err := db.ExecContext(r.Context(), `DELETE FROM pets WHERE id = $1`, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		http.Error(w, "pet not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
