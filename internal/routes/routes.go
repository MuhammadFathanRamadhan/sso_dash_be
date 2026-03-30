package routes

import (
	"time"

	"dashboard-sso/internal/handlers"
	"dashboard-sso/internal/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

func Setup(app *fiber.App, h *handlers.AuthHandler) {
	auth := app.Group("/auth")

	// Rate limiter khusus auth: 10 request per 15 menit per IP
	authLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: 15 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"message": "Terlalu banyak percobaan. Coba lagi dalam 15 menit.",
			})
		},
	})

	// ── Public ──────────────────────────────────────
	auth.Post("/register", authLimiter, h.Register)
	auth.Post("/request-otp", authLimiter, h.RequestOtp)
	auth.Post("/verify-otp", authLimiter, h.VerifyOtp)
	auth.Get("/confirm-delete", h.ConfirmDelete)

	// ── Protected ───────────────────────────────────
	protected := auth.Group("", middleware.AuthRequired)

	// Profile
	protected.Get("/me", h.GetMe)
	protected.Get("/stats", h.GetStats)

	// Sessions
	protected.Get("/sessions", h.GetSessions)
	protected.Post("/logout", h.Logout)
	protected.Post("/logout-others", h.LogoutOthers)
	protected.Post("/sessions/:id/logout", h.LogoutSession)

	// Alerts
	protected.Get("/alerts", h.GetAlerts)
	protected.Patch("/alerts/clear", h.ClearAlerts)
	protected.Patch("/alerts/:id/read", h.MarkAlertRead)

	// Account
	protected.Post("/request-delete", h.RequestDelete)

	// Apps
	protected.Get("/apps", h.GetUserApps)
	protected.Post("/apps/connect", h.ConnectApp)
	protected.Post("/apps/:slug/disconnect", h.DisconnectApp)
	protected.Post("/apps/:slug/log-access", h.LogAppAccess)
	protected.Get("/recent-activity", h.GetRecentActivity)
}