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
	ID    uint   `json:"id" gorm:"primaryKey"`
	Name  string `json:"name"`
	Email string `json:"email" gorm:"unique"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Users   []User `json:"users,omitempty"`
	User    *User  `json:"user,omitempty"`
}

var db *gorm.DB

// Initialize the database connection
func initDatabase() {
	dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
	var err error
	// Open connection to PostgreSQL
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to PostgreSQL server:", err)
	}

	// Auto migrate the User model
	db.AutoMigrate(&User{})
}

// Add a new user to the database
func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil || user.Name == "" || user.Email == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Add the user to the database
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, "Failed to add user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User added successfully", User: &user})
}

// Delete a user by ID
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(data["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	result := db.Delete(&User{}, id)
	if result.Error != nil || result.RowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User deleted successfully"})
}

// Fetch all users
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	var users []User
	result := db.Find(&users)
	if result.Error != nil {
		http.Error(w, "Error fetching users", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(Response{
		Status: "success",
		Users:  users,
	})
}

// Update an existing user
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		log.Println("Error decoding JSON:", err)
		return
	}

	// Проверка, что все обязательные поля присутствуют
	if user.ID == 0 || user.Name == "" || user.Email == "" {
		http.Error(w, "Missing required fields: ID, Name or Email", http.StatusBadRequest)
		log.Println("Missing fields:", user)
		return
	}

	// Update user data in the database
	result := db.Model(&User{}).Where("id = ?", user.ID).Updates(User{Name: user.Name, Email: user.Email})
	if result.Error != nil || result.RowsAffected == 0 {
		http.Error(w, "User not found or update failed", http.StatusNotFound)
		log.Println("User update failed:", result.Error)
		return
	}

	// Send success message
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User updated successfully"})
}

func main() {
	// Инициализация базы данных
	initDatabase()

	// Определяем маршруты
	http.HandleFunc("/add-user", addUserHandler)
	http.HandleFunc("/delete-user", deleteUserHandler)
	http.HandleFunc("/get-users", getUsersHandler)
	http.HandleFunc("/update-user", updateUserHandler)

	// Включаем CORS для всех источников
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
	})

	// Оборачиваем стандартный HTTP обработчик в CORS
	handler := c.Handler(http.DefaultServeMux)

	// Запуск сервера
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
