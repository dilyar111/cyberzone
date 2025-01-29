package main

import "testing"

func TestCalculateRentalCost(t *testing.T) {
	hours := 5
	ratePerHour := 50.0
	expectedCost := 250.0

	cost := CalculateRentalCost(hours, ratePerHour)

	if cost != expectedCost {
		t.Errorf("Incorrect rental cost. Expected: %.2f, Got: %.2f", expectedCost, cost)
	}
}

func CalculateRentalCost(hours int, ratePerHour float64) any {
	panic("unimplemented")
}
