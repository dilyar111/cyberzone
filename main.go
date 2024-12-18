package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/rs/cors"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type User struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	Name      string `json:"name"`
	Email     string `json:"email" gorm:"unique"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Users   []User `json:"users,omitempty"`
}

var db *gorm.DB

// Check if the database exists, and if not, create it
func initDatabase() {
	dsn := "user=postgres password=postgres sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to the PostgreSQL server:", err)
	}

	var result int
	err = db.Raw("SELECT 1 FROM pg_database WHERE datname = ?", "gaming_club").Scan(&result).Error
	if err != nil || result != 1 {
		fmt.Println("Database does not exist. Creating database...")
		err = db.Exec("CREATE DATABASE gaming_club").Error
		if err != nil {
			log.Fatal("Failed to create database:", err)
		}
	}

	dsn = "user=postgres password=postgres dbname=gaming_club sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to the gaming_club database:", err)
	}

	db.AutoMigrate(&User{})
}

// Handler for validating JSON payloads
func handleJSONValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Status: "fail", Message: "Method not allowed"})
		return
	}

	var payload map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Status: "fail", Message: "Invalid JSON format"})
		return
	}

	message, ok := payload["message"]
	if !ok || fmt.Sprintf("%T", message) != "string" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Status: "fail", Message: "Invalid JSON message"})
		return
	}

	fmt.Println("Message received:", message)
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "Data successfully received"})
}

// Existing handler for adding a user
func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil || user.Name == "" || user.Email == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	db.Create(&user)
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User added successfully"})
}

// Existing handler for deleting a user
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(data["id"])
	if err != nil || id <= 0 {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	db.Delete(&User{}, id)
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User deleted successfully"})
}

// Existing handler for retrieving users
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	var users []User
	db.Find(&users)
	json.NewEncoder(w).Encode(Response{Status: "success", Users: users})
}

func main() {
	initDatabase()

	// Handlers
	http.HandleFunc("/", handleJSONValidation)
	http.HandleFunc("/add-user", addUserHandler)
	http.HandleFunc("/delete-user", deleteUserHandler)
	http.HandleFunc("/get-users", getUsersHandler)

	// CORS handler
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
	})

	handler := c.Handler(http.DefaultServeMux)

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
