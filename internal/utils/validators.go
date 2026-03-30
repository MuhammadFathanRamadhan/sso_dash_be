package utils

import "regexp"

var (
	emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	phoneRegex = regexp.MustCompile(`^[0-9]{8,15}$`)
)

func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func IsValidPhone(phone string) bool {
	return phoneRegex.MatchString(phone)
}