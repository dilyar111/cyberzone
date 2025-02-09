package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"

	"github.com/gorilla/websocket"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/rand"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// =====================
// Структуры для базы данных
// =====================

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string
	Email     string `gorm:"unique"`
	Password  string
	Role      string // например, "User", "Admin"
	Verified  bool   `gorm:"default:false"`
	OTP       string `json:"otp,omitempty"`
	OTPExpiry time.Time `json:"otp_expiry,omitempty"`
}

type TempUser struct {
	ID               uint   `gorm:"primaryKey"`
	Name             string
	Email            string `gorm:"unique"`
	Password         string
	VerificationCode string
}

var (
	db      *gorm.DB
	limiter = rate.NewLimiter(1, 3)
)

// =====================
// Логирование в файл JSON
// =====================

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

func writeLogToFile(level, message string) {
	logEntry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}

	file, err := os.OpenFile("server_logs.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(logEntry); err != nil {
		log.Fatalf("Error writing log entry: %v", err)
	}
}

// =====================
// Инициализация базы данных
// =====================

func initDatabase() {
	dsn := "postgres://postgres:postgres@localhost/gaming_club?sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	db.AutoMigrate(&User{}, &TempUser{}, &Message{})
	log.Println("Database initialized successfully")
}

// =====================
// Middleware: rate limiting
// =====================

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			logrus.Error("Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// =====================
// Функции для регистрации, верификации и логина
// =====================

// Генерация случайного кода подтверждения
func generateVerificationCode() string {
	rand.Seed(uint64(time.Now().UnixNano()))
	return fmt.Sprintf("%04d", rand.Intn(10000))
}

// Отправка Email
func sendEmail(to, subject, message string) {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	auth := smtp.PlainAuth("", "mirasbeyse@gmail.com", "fhqj slmp jexj vkrf", smtpHost)

	msg := fmt.Sprintf("From: mirasbeyse@gmail.com\nTo: %s\nSubject: %s\n\n%s", to, subject, message)

	log.Printf("Sending email to %s with subject %s", to, subject)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, "mirasbeyse@gmail.com", []string{to}, []byte(msg))
	if err != nil {
		log.Printf("Error sending email: %v", err)
	} else {
		log.Printf("Email sent to %s", to)
	}
}

// Регистрация с верификацией Email
func signUpHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to decode user data: %v", err))
		http.Error(w, `{"error":"Invalid input"}`, http.StatusBadRequest)
		return
	}

	var existingUser User
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		writeLogToFile("error", fmt.Sprintf("Email already registered: %s", user.Email))
		http.Error(w, `{"error":"Email is already registered"}`, http.StatusConflict)
		return
	}

	verificationCode := generateVerificationCode()

	tempUser := TempUser{
		Name:             user.Name,
		Email:            user.Email,
		Password:         user.Password,
		VerificationCode: verificationCode,
	}

	if err := db.Create(&tempUser).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to create temp user in DB: %v", err))
		http.Error(w, `{"error":"Failed to create temporary user"}`, http.StatusInternalServerError)
		return
	}

	go sendEmail(user.Email, "Verification Code", verificationCode)

	writeLogToFile("info", fmt.Sprintf("Verification code sent to: %s", user.Email))
	json.NewEncoder(w).Encode(map[string]string{"message": "Verification code sent"})
}

// Верификация email
func verifyCode(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		writeLogToFile("error", fmt.Sprintf("Invalid JSON format: %v", err))
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	var tempUser TempUser
	if err := db.Where("email = ? AND verification_code = ?", requestData.Email, requestData.Code).First(&tempUser).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Invalid verification code for email: %s", requestData.Email))
		http.Error(w, `{"error":"Invalid verification code"}`, http.StatusNotFound)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(tempUser.Password), bcrypt.DefaultCost)
	user := User{
		Name:     tempUser.Name,
		Email:    tempUser.Email,
		Password: string(hashedPassword),
		Role:     "User",
		Verified: true,
	}

	if err := db.Create(&user).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to create verified user: %v", err))
		http.Error(w, `{"error":"Failed to create verified user"}`, http.StatusInternalServerError)
		return
	}

	if err := db.Delete(&tempUser).Error; err != nil {
		writeLogToFile("error", fmt.Sprintf("Failed to delete temp user: %v", err))
	}

	writeLogToFile("info", fmt.Sprintf("Email verified for: %s", requestData.Email))
	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified, you can login now."})
}

// Логин с OTP
func login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	if !user.Verified {
		http.Error(w, `{"error":"Email is not verified"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, `{"error":"Invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
	user.OTP = otp
	user.OTPExpiry = time.Now().Add(5 * time.Minute)
	db.Save(&user)

	go sendEmail(user.Email, "Your OTP for login", otp)

	writeLogToFile("info", fmt.Sprintf("OTP sent to: %s", user.Email))
	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP sent to your email.",
	})
}

func verifyOTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	if user.OTP != input.OTP || time.Now().After(user.OTPExpiry) {
		http.Error(w, `{"error": "Invalid or expired OTP"}`, http.StatusUnauthorized)
		return
	}

	token, err := generateToken(user)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	writeLogToFile("info", fmt.Sprintf("Login successful for: %s", input.Email))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
		"token":   token,
		"role":    user.Role,
	})
}

// Генерация JWT токена
func generateToken(user User) (string, error) {
	claims := jwt.MapClaims{
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("t/PsFMLt6kqMC4WKEpXbTxuysx1bolhhi2rshUJXttE="))
}

// Проверка токена
func validateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("t/PsFMLt6kqMC4WKEpXbTxuysx1bolhhi2rshUJXttE="), nil
	})
	return token, err
}

// Middleware для защиты (пример для админских маршрутов)
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenString = tokenString[7:]
		token, err := validateToken(tokenString)
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		role := claims["role"].(string)
		if role != "Admin" {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Пример защищённого маршрута для админов
func adminHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "Welcome to the Admin panel"})
}

// =====================
// Реализация чата через WebSocket с разделением по ролям
// =====================

// Расширенная структура сообщения (добавлено поле SenderRole)
type Message struct {
	ID         uint      `gorm:"primaryKey"`
	ChatID     string    `gorm:"not null"`
	Username   string    `gorm:"not null"`
	Content    string    `gorm:"not null"`
	Timestamp  time.Time `gorm:"not null"`
	Status     string    `gorm:"default:'active'"`
	SenderRole string    `gorm:"not null"`
	Email      string    `gorm:"not null"` // Жаңа өріс: пайдаланушының электрондық поштасы
}


func saveMessage(chatID, username, content, role, email string) {
	msg := Message{
		ChatID:     chatID,
		Username:   username,
		Content:    content,
		Timestamp:  time.Now(),
		Status:     "active",
		SenderRole: role, // Рөлді беру
		Email:      email, // Пайдаланушының электрондық поштасын беру
	}

	err := db.Create(&msg).Error
	if err != nil {
		log.Println("Error saving message:", err)
	}
}

func sendMessageHistory(ws *websocket.Conn, chatID string) {
	var messages []Message
	if err := db.Where("chat_id = ?", chatID).Order("timestamp ASC").Find(&messages).Error; err != nil {
		log.Println("Error retrieving message history:", err)
		return
	}

	// Отправляем историю сообщений клиенту
	for _, msg := range messages {
		if err := ws.WriteJSON(msg); err != nil {
			log.Println("Error sending message to client:", err)
		}
	}
}
// Задаём почту, на которую будут приходить сообщения (укажите свой адрес)
var adminEmail = "nurbibirahmanberdy@gmail.com"

// Для WebSocket‑подключений различаем по query-параметру
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Для хранения соединения клиента – сопоставляем chatID с соединением
var clientConns = make(map[string]*websocket.Conn)

// Для администратора (предполагается один активный админ)
var adminConn *websocket.Conn

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer ws.Close()

	role := r.URL.Query().Get("role")
	var chatID string

	if role == "admin" {
		adminConn = ws
		log.Println("Admin connected via WebSocket")
	} else {
		chatID = r.URL.Query().Get("chat_id")
		if chatID == "" {
			chatID = fmt.Sprintf("chat_%d", time.Now().UnixNano()) // Новый chatID для клиента
		}
		clientConns[chatID] = ws
		ws.WriteJSON(map[string]string{"chat_id": chatID})
		log.Printf("Client connected with chat_id=%s", chatID)

		// Отправляем историю сообщений клиенту
		sendMessageHistory(ws, chatID)
	}

	// Чтение сообщений из соединения
	for {
		var msg Message
		err := ws.ReadJSON(&msg)
		if err != nil {
			log.Println("WebSocket read error:", err)
			if role == "admin" {
				adminConn = nil
			} else {
				delete(clientConns, msg.ChatID)
			}
			break
		}
	
		// ЛОГ: Хабарламаның нақты мәндері қандай екенін көрейік
		log.Printf("DEBUG: Received message -> Username: %s, Email: %s, Content: %s, Role: %s", 
			msg.Username, msg.Email, msg.Content, role)
	
		if msg.Username == "" || msg.Email == "" {
			log.Println("WARNING: Username or Email is EMPTY!")
		}
	
		msg.Timestamp = time.Now()
		msg.SenderRole = role
	
		saveMessage(chatID, msg.Username, msg.Content, role, msg.Email)
	
		// Хабарламаны басқа тарапқа жіберу
		if role == "client" {
			// Отправляем сообщение на почту (если задан адрес)
			if adminEmail != "" {
				sendEmail(adminEmail, "New Chat Message", fmt.Sprintf("From chat %s: %s", msg.ChatID, msg.Content))
			}
			if adminConn != nil {
				if err := adminConn.WriteJSON(msg); err != nil {
					log.Println("Error sending message to admin:", err)
				}
			} else {
				log.Println("Admin not connected; message not forwarded.")
			}
		} else if role == "admin" {
			if client, ok := clientConns[msg.ChatID]; ok {
				if err := client.WriteJSON(msg); err != nil {
					log.Println("Error sending message to client:", err)
				}
			} else {
				log.Printf("No client found with chat_id: %s", msg.ChatID)
			}
		}
	}
}	


// =====================
// Главная функция: запуск сервера
// =====================

func main() {
	initDatabase()
	mux := http.NewServeMux()

	// Обработчики для публичных маршрутов
	mux.HandleFunc("/signup", signUpHandler)
	mux.HandleFunc("/verify-code", verifyCode)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/verify-otp", verifyOTP)

	// Пример защищённого маршрута для админов
	mux.Handle("/admin", authMiddleware(http.HandlerFunc(adminHandler)))

	// Маршрут для WebSocket-чата
	mux.HandleFunc("/ws", handleConnections)

	// Применяем middleware (rate limiting, CORS)
	handler := rateLimitMiddleware(cors.Default().Handler(mux))

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}