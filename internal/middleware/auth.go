package middleware

import (
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	SessionID string `json:"sessionId"`
}

func AuthRequired(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Token tidak ditemukan",
		})
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Token tidak valid atau kedaluwarsa",
		})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Token tidak valid",
		})
	}

	c.Locals("userId", claims["userId"])
	c.Locals("email", claims["email"])
	c.Locals("name", claims["name"])
	c.Locals("sessionId", claims["sessionId"])
	c.Locals("rawToken", tokenStr)

	return c.Next()
}

func GetUserID(c *fiber.Ctx) string {
	v, _ := c.Locals("userId").(string)
	return v
}

func GetSessionID(c *fiber.Ctx) string {
	v, _ := c.Locals("sessionId").(string)
	return v
}

func GetRawToken(c *fiber.Ctx) string {
	v, _ := c.Locals("rawToken").(string)
	return v
}