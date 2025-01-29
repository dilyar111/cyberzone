package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUserHandler(t *testing.T) {
	request, _ := http.NewRequest("GET", "/get-user?id=1", nil)
	response := httptest.NewRecorder()

	getUserHandler(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, response.Code)
	}

	expected := `{"user":{"id":1,"name":"John Doe","email":"john@example.com"}}`
	if response.Body.String() != expected {
		t.Errorf("Incorrect response body. Expected: %s, Got: %s", expected, response.Body.String())
	}
}
