// @title           Dashboard SSO API
// @version         1.0
// @description     REST API untuk sistem Single Sign-On Dashboard BOMA
// @host            localhost:4000
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     Masukkan token dengan format: Bearer {token}
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"dashboard-sso/config"
	_ "dashboard-sso/docs"
	"dashboard-sso/internal/handlers"
	"dashboard-sso/internal/repositories"
	"dashboard-sso/internal/routes"
	"dashboard-sso/internal/services"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	fiberSwagger "github.com/gofiber/swagger"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env
	if err := godotenv.Load(); err != nil {
		log.Println("File .env tidak ditemukan, menggunakan environment variables sistem")
	}

	// Init database
	db := config.GetDB()

	// Init dependencies
	userRepo := repositories.NewUserRepository(db)
	delTokenRepo := repositories.NewDeleteTokenRepository(db)
	otpSvc := services.NewOtpService(db)
	authSvc := services.NewAuthService(db, userRepo, delTokenRepo, otpSvc)
	authHandler := handlers.NewAuthHandler(authSvc)

	// Init Fiber
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"message": err.Error()})
		},
	})

	// Middleware
	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		allowedOrigins = "*"
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, PATCH, DELETE, OPTIONS",
	}))

	// Global rate limiter: 100 request per 15 menit per IP
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 15 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"message": "Terlalu banyak permintaan. Coba lagi nanti.",
			})
		},
	}))

	// Swagger UI
	app.Get("/swagger/*", fiberSwagger.HandlerDefault)

	// Routes
	routes.Setup(app, authHandler)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}

	fmt.Printf("Server berjalan di http://localhost:%s\n", port)
	fmt.Printf("Swagger UI   di http://localhost:%s/swagger/\n", port)
	log.Fatal(app.Listen(":" + port))
}