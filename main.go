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

func initDatabase() {
	dsn := "user=postgres password=postgres sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to PostgreSQL server:", err)
	}

	db.Exec("CREATE DATABASE IF NOT EXISTS gaming_club")

	db, err = gorm.Open(postgres.Open("user=postgres password=postgres dbname=gaming_club sslmode=disable"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to gaming_club database:", err)
	}

	db.AutoMigrate(&User{})
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil || user.Name == "" || user.Email == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	db.Create(&user)
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User added successfully", User: &user})
}

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
	db.Delete(&User{}, id)
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User deleted successfully"})
}

func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	var users []User
	db.Find(&users)
	json.NewEncoder(w).Encode(Response{Status: "success", Users: users})
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil || user.ID == 0 || user.Name == "" || user.Email == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	result := db.Model(&User{}).Where("id = ?", user.ID).Updates(User{Name: user.Name, Email: user.Email})
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(Response{Status: "success", Message: "User updated successfully"})
}

func main() {
	initDatabase()

	http.HandleFunc("/add-user", addUserHandler)
	http.HandleFunc("/delete-user", deleteUserHandler)
	http.HandleFunc("/get-users", getUsersHandler)
	http.HandleFunc("/update-user", updateUserHandler)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
	})

	handler := c.Handler(http.DefaultServeMux)
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
