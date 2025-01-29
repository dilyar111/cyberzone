package main

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/tebeka/selenium"
)

func setupDatabase() error {
	var err error
	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	// Создайте таблицы или данные, если это необходимо для тестов
	return nil
}

func TestAdminLogin(t *testing.T) {
	const (
		seleniumPath    = "/Users/dilyarabaizova/Downloads/selenium-server-standalone.jar" // Укажите путь к selenium-server-standalone.jar
		geckoDriverPath = "/Users/dilyarabaizova/Downloads/chromedriver"                   // Путь к chromedriver
		port            = 8080
	)

	// Проверка, инициализирована ли база данных
	if db == nil {
		t.Fatal("Database connection is not initialized")
	}

	// Настройка и запуск Selenium сервер и драйвера
	opts := []selenium.ServiceOption{}
	service, err := selenium.NewChromeDriverService(geckoDriverPath, port, opts...)
	if err != nil {
		t.Fatalf("Error starting the ChromeDriver server: %v", err)
	}
	defer service.Stop()

	// Запуск WebDriver
	caps := selenium.Capabilities{"browserName": "chrome"}
	wd, err := selenium.NewRemote(caps, "http://localhost:"+string(port))
	if err != nil {
		t.Fatalf("Error connecting to WebDriver: %v", err)
	}
	defer wd.Quit()

	// Переход на страницу входа
	wd.Get("http://localhost:8080/admin")
	usernameInput, _ := wd.FindElement(selenium.ByID, "username")
	passwordInput, _ := wd.FindElement(selenium.ByID, "password")
	loginButton, _ := wd.FindElement(selenium.ByID, "login-button")

	// Ввод данных для входа
	usernameInput.SendKeys("admin")
	passwordInput.SendKeys("securepassword")
	loginButton.Click()

	// Проверка, что после входа появляется "Admin Dashboard"
	dashboardHeader, err := wd.FindElement(selenium.ByTagName, "h1")
	if err != nil {
		t.Fatalf("Could not find dashboard header: %v", err)
	}
	headerText, _ := dashboardHeader.Text()
	if headerText != "Admin Dashboard" {
		t.Errorf("Expected 'Admin Dashboard', got '%s'", headerText)
	}
}
