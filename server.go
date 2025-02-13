package main

import (
	"fmt"
	"log"
	"net/http"
	
	"time"

	"github.com/gorilla/websocket"

)

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
	
		if msg.Email == "" {
			log.Println("WARNING: Email is EMPTY!")
		}
	
		msg.Timestamp = time.Now()
		msg.SenderRole = role
	
		saveMessage(chatID, msg.Username, msg.Content, role, msg.Email)
	
		// Хабарламаны басқа тарапқа жіберу
		if role == "client" {
			// Хабарламаны админге жіберу
			if adminConn != nil {
				if err := adminConn.WriteJSON(msg); err != nil {
					log.Println("Error sending message to admin:", err)
				}
			} else {
				log.Println("Admin not connected; message not forwarded.")
			}
		
			// Клиентке өзінің хабарламасын жіберу
			if client, ok := clientConns[msg.ChatID]; ok {
				if err := client.WriteJSON(msg); err != nil {
					log.Println("Error sending message to client:", err)
				}
			}
		} else if role == "admin" {
			// Админ хабарламасын клиентке жіберу
			if client, ok := clientConns[msg.ChatID]; ok {
				if err := client.WriteJSON(msg); err != nil {
					log.Println("Error sending message to client:", err)
				}
			} else {
				log.Println("Client not connected; message not forwarded.")
			}
		}		
	}
}	

