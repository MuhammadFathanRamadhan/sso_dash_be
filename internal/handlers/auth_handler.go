package handlers

import (
	"errors"

	"dashboard-sso/internal/middleware"
	"dashboard-sso/internal/services"

	"github.com/gofiber/fiber/v2"
)

// ──────────────────────────────────────────────────
// Request / Response types (untuk Swagger docs)
// ──────────────────────────────────────────────────

type RegisterRequest struct {
	Name  string `json:"name"  example:"Muhammad Fathan Ramadhan"`
	Email string `json:"email" example:"fathan@example.com"`
	Phone string `json:"phone" example:"08123456789"`
}

type RequestOtpRequest struct {
	Email string `json:"email" example:"fathan@example.com"`
}

type ConnectAppRequest struct {
	Slug string `json:"slug" example:"my-app"`
}

type MessageResponse struct {
	Message string `json:"message" example:"Berhasil"`
}

type ErrorResponse struct {
	Message string `json:"message" example:"Terjadi kesalahan"`
	Error   string `json:"error,omitempty" example:"detail error"`
}

// ──────────────────────────────────────────────────
// Handler struct
// ──────────────────────────────────────────────────

type AuthHandler struct {
	svc *services.AuthService
}

func NewAuthHandler(svc *services.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// ──────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────

func handleErr(c *fiber.Ctx, err error, defaultMsg string) error {
	var appErr *services.AppError
	if errors.As(err, &appErr) {
		return c.Status(appErr.Status).JSON(fiber.Map{"message": appErr.Message})
	}
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"message": defaultMsg,
		"error":   err.Error(),
	})
}

// ──────────────────────────────────────────────────
// POST /auth/register
// ──────────────────────────────────────────────────

// Register godoc
// @Summary      Daftarkan akun baru
// @Description  Membuat akun pengguna baru dengan nama, email, dan nomor telepon
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      RegisterRequest  true  "Data registrasi"
// @Success      201   {object}  map[string]interface{}
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var body RegisterRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Request body tidak valid"})
	}

	user, err := h.svc.Register(body.Name, body.Email, body.Phone)
	if err != nil {
		return handleErr(c, err, "Gagal membuat akun")
	}
	return c.Status(201).JSON(fiber.Map{"message": "Akun berhasil dibuat", "user": user})
}

// ──────────────────────────────────────────────────
// POST /auth/request-otp
// ──────────────────────────────────────────────────

// RequestOtp godoc
// @Summary      Kirim OTP ke email
// @Description  Mengirimkan kode OTP ke alamat email yang terdaftar
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      RequestOtpRequest  true  "Email terdaftar"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /auth/request-otp [post]
func (h *AuthHandler) RequestOtp(c *fiber.Ctx) error {
	var body RequestOtpRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Request body tidak valid"})
	}

	user, err := h.svc.RequestOtp(body.Email)
	if err != nil {
		return handleErr(c, err, "Gagal kirim OTP")
	}
	return c.JSON(fiber.Map{"message": "OTP terkirim", "user": user})
}

// ──────────────────────────────────────────────────
// POST /auth/verify-otp
// ──────────────────────────────────────────────────

// VerifyOtp godoc
// @Summary      Verifikasi OTP dan login
// @Description  Memverifikasi kode OTP dan mengembalikan JWT token sesi
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      services.VerifyOtpRequest  true  "Email, OTP, dan info perangkat"
// @Success      200   {object}  services.VerifyOtpResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      429   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /auth/verify-otp [post]
func (h *AuthHandler) VerifyOtp(c *fiber.Ctx) error {
	var req services.VerifyOtpRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Request body tidak valid"})
	}

	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}
	ipAddress := c.IP()

	result, err := h.svc.VerifyOtp(req, userAgent, ipAddress)
	if err != nil {
		return handleErr(c, err, "Gagal verifikasi OTP")
	}
	return c.JSON(result)
}

// ──────────────────────────────────────────────────
// GET /auth/me
// ──────────────────────────────────────────────────

// GetMe godoc
// @Summary      Profil pengguna saat ini
// @Description  Mengembalikan data profil pengguna yang sedang login
// @Tags         Profile
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/me [get]
func (h *AuthHandler) GetMe(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	user, err := h.svc.GetMe(userID)
	if err != nil {
		return handleErr(c, err, "Gagal mengambil data user")
	}
	return c.JSON(fiber.Map{"user": user})
}

// ──────────────────────────────────────────────────
// GET /auth/stats
// ──────────────────────────────────────────────────

// GetStats godoc
// @Summary      Statistik pengguna
// @Description  Mengembalikan statistik aktivitas pengguna
// @Tags         Profile
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/stats [get]
func (h *AuthHandler) GetStats(c *fiber.Ctx) error {
	stats, err := h.svc.GetStats(middleware.GetUserID(c))
	if err != nil {
		return handleErr(c, err, "Gagal mengambil statistik")
	}
	return c.JSON(stats)
}

// ──────────────────────────────────────────────────
// POST /auth/logout
// ──────────────────────────────────────────────────

// Logout godoc
// @Summary      Logout sesi saat ini
// @Description  Mengakhiri sesi login yang sedang aktif
// @Tags         Sessions
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/logout [post]
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	if err := h.svc.Logout(middleware.GetUserID(c), middleware.GetSessionID(c)); err != nil {
		return handleErr(c, err, "Gagal logout")
	}
	return c.JSON(fiber.Map{"message": "Logout berhasil"})
}

// ──────────────────────────────────────────────────
// POST /auth/logout-others
// ──────────────────────────────────────────────────

// LogoutOthers godoc
// @Summary      Logout semua perangkat lain
// @Description  Mengakhiri semua sesi login kecuali sesi saat ini
// @Tags         Sessions
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/logout-others [post]
func (h *AuthHandler) LogoutOthers(c *fiber.Ctx) error {
	err := h.svc.LogoutOthers(
		middleware.GetUserID(c),
		middleware.GetSessionID(c),
		middleware.GetRawToken(c),
	)
	if err != nil {
		return handleErr(c, err, "Gagal mengeluarkan perangkat lain")
	}
	return c.JSON(fiber.Map{"message": "Semua perangkat lain telah dikeluarkan"})
}

// ──────────────────────────────────────────────────
// GET /auth/sessions
// ──────────────────────────────────────────────────

// GetSessions godoc
// @Summary      Daftar sesi aktif
// @Description  Mengembalikan semua sesi login yang sedang aktif
// @Tags         Sessions
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  []map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/sessions [get]
func (h *AuthHandler) GetSessions(c *fiber.Ctx) error {
	sessions, err := h.svc.GetSessions(middleware.GetUserID(c))
	if err != nil {
		return handleErr(c, err, "Gagal mengambil sesi")
	}
	return c.JSON(sessions)
}

// ──────────────────────────────────────────────────
// POST /auth/sessions/:id/logout
// ──────────────────────────────────────────────────

// LogoutSession godoc
// @Summary      Logout sesi tertentu
// @Description  Mengakhiri sesi login berdasarkan ID sesi
// @Tags         Sessions
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Session ID"
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/sessions/{id}/logout [post]
func (h *AuthHandler) LogoutSession(c *fiber.Ctx) error {
	err := h.svc.LogoutSession(middleware.GetUserID(c), c.Params("id"))
	if err != nil {
		return handleErr(c, err, "Gagal mengeluarkan perangkat")
	}
	return c.JSON(fiber.Map{"message": "Perangkat berhasil dikeluarkan"})
}

// ──────────────────────────────────────────────────
// GET /auth/alerts
// ──────────────────────────────────────────────────

// GetAlerts godoc
// @Summary      Daftar notifikasi login
// @Description  Mengembalikan riwayat notifikasi aktivitas login
// @Tags         Alerts
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  []map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/alerts [get]
func (h *AuthHandler) GetAlerts(c *fiber.Ctx) error {
	alerts, err := h.svc.GetAlerts(middleware.GetUserID(c))
	if err != nil {
		return handleErr(c, err, "Gagal mengambil alerts")
	}
	return c.JSON(alerts)
}

// ──────────────────────────────────────────────────
// PATCH /auth/alerts/:id/read
// ──────────────────────────────────────────────────

// MarkAlertRead godoc
// @Summary      Tandai notifikasi sudah dibaca
// @Description  Menandai notifikasi tertentu sebagai sudah dibaca
// @Tags         Alerts
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Alert ID"
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/alerts/{id}/read [patch]
func (h *AuthHandler) MarkAlertRead(c *fiber.Ctx) error {
	if err := h.svc.MarkAlertRead(middleware.GetUserID(c), c.Params("id")); err != nil {
		return handleErr(c, err, "Gagal update alert")
	}
	return c.JSON(fiber.Map{"message": "Marked as read"})
}

// ──────────────────────────────────────────────────
// PATCH /auth/alerts/clear
// ──────────────────────────────────────────────────

// ClearAlerts godoc
// @Summary      Hapus semua notifikasi
// @Description  Menghapus seluruh riwayat notifikasi login pengguna
// @Tags         Alerts
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/alerts/clear [patch]
func (h *AuthHandler) ClearAlerts(c *fiber.Ctx) error {
	if err := h.svc.ClearAlerts(middleware.GetUserID(c)); err != nil {
		return handleErr(c, err, "Gagal clear alerts")
	}
	return c.JSON(fiber.Map{"message": "All alerts cleared"})
}

// ──────────────────────────────────────────────────
// POST /auth/request-delete
// ──────────────────────────────────────────────────

// RequestDelete godoc
// @Summary      Minta penghapusan akun
// @Description  Mengirimkan email konfirmasi untuk penghapusan akun permanen
// @Tags         Account
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/request-delete [post]
func (h *AuthHandler) RequestDelete(c *fiber.Ctx) error {
	if err := h.svc.RequestAccountDeletion(middleware.GetUserID(c)); err != nil {
		return handleErr(c, err, "Gagal mengirim email konfirmasi")
	}
	return c.JSON(fiber.Map{"message": "Email konfirmasi penghapusan akun telah dikirim. Silakan cek inbox Anda."})
}

// ──────────────────────────────────────────────────
// GET /auth/confirm-delete?token=...
// ──────────────────────────────────────────────────

// ConfirmDelete godoc
// @Summary      Konfirmasi penghapusan akun
// @Description  Mengkonfirmasi penghapusan akun melalui token dari email (mengembalikan halaman HTML)
// @Tags         Account
// @Produce      html
// @Param        token  query     string  true  "Token konfirmasi dari email"
// @Success      200    {string}  string  "Halaman HTML konfirmasi"
// @Failure      400    {string}  string  "Halaman HTML error"
// @Router       /auth/confirm-delete [get]
func (h *AuthHandler) ConfirmDelete(c *fiber.Ctx) error {
	token := c.Query("token")
	c.Type("html")

	if err := h.svc.ConfirmAccountDeletion(token); err != nil {
		msg := "Terjadi kesalahan. Silakan coba lagi."
		var appErr *services.AppError
		if errors.As(err, &appErr) {
			msg = appErr.Message
		}
		return c.Status(400).SendString(`<!DOCTYPE html>
<html lang="id">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gagal Menghapus Akun</title></head>
<body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f9fafb">
  <div style="max-width:420px;width:90%;padding:32px;border:1px solid #e0e0e0;border-radius:12px;text-align:center;background:#fff">
    <div style="font-size:48px;margin-bottom:16px">⚠️</div>
    <h2 style="color:#b91c1c;margin-bottom:8px">Gagal Menghapus Akun</h2>
    <p style="color:#6b7280;font-size:14px">` + msg + `</p>
    <p style="color:#9ca3af;font-size:12px;margin-top:24px">© BOMA SSO | All Rights Reserved</p>
  </div>
</body>
</html>`)
	}

	return c.SendString(`<!DOCTYPE html>
<html lang="id">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Akun Dihapus</title></head>
<body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f9fafb">
  <div style="max-width:420px;width:90%;padding:32px;border:1px solid #e0e0e0;border-radius:12px;text-align:center;background:#fff">
    <div style="font-size:48px;margin-bottom:16px">🗑️</div>
    <h2 style="color:#103B74;margin-bottom:8px">Akun Berhasil Dihapus</h2>
    <p style="color:#6b7280;font-size:14px">Seluruh data akun BOMA Anda telah dihapus secara permanen. Terima kasih telah menggunakan layanan kami.</p>
    <p style="color:#9ca3af;font-size:12px;margin-top:24px">© BOMA SSO | All Rights Reserved</p>
  </div>
</body>
</html>`)
}

// ──────────────────────────────────────────────────
// GET /auth/apps
// ──────────────────────────────────────────────────

// GetUserApps godoc
// @Summary      Daftar aplikasi terhubung
// @Description  Mengembalikan semua aplikasi yang terhubung dengan akun pengguna
// @Tags         Apps
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/apps [get]
func (h *AuthHandler) GetUserApps(c *fiber.Ctx) error {
	apps, err := h.svc.GetUserApps(middleware.GetUserID(c))
	if err != nil {
		return handleErr(c, err, "Gagal mengambil data aplikasi")
	}
	return c.JSON(fiber.Map{"apps": apps})
}

// ──────────────────────────────────────────────────
// POST /auth/apps/connect
// ──────────────────────────────────────────────────

// ConnectApp godoc
// @Summary      Hubungkan ke aplikasi
// @Description  Menghubungkan akun pengguna dengan aplikasi berdasarkan slug
// @Tags         Apps
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      ConnectAppRequest  true  "Slug aplikasi"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /auth/apps/connect [post]
func (h *AuthHandler) ConnectApp(c *fiber.Ctx) error {
	var body ConnectAppRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Request body tidak valid"})
	}

	msg, app, err := h.svc.ConnectApp(middleware.GetUserID(c), body.Slug)
	if err != nil {
		return handleErr(c, err, "Gagal menghubungkan aplikasi")
	}
	return c.JSON(fiber.Map{"message": msg, "app": app})
}

// ──────────────────────────────────────────────────
// POST /auth/apps/:slug/disconnect
// ──────────────────────────────────────────────────

// DisconnectApp godoc
// @Summary      Putuskan koneksi aplikasi
// @Description  Memutuskan koneksi akun pengguna dari aplikasi
// @Tags         Apps
// @Produce      json
// @Security     BearerAuth
// @Param        slug  path      string  true  "Slug aplikasi"
// @Success      200   {object}  MessageResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /auth/apps/{slug}/disconnect [post]
func (h *AuthHandler) DisconnectApp(c *fiber.Ctx) error {
	if err := h.svc.DisconnectApp(middleware.GetUserID(c), c.Params("slug")); err != nil {
		return handleErr(c, err, "Gagal memutuskan aplikasi")
	}
	return c.JSON(fiber.Map{"message": "Aplikasi berhasil diputuskan"})
}

// ──────────────────────────────────────────────────
// POST /auth/apps/:slug/log-access
// ──────────────────────────────────────────────────

// LogAppAccess godoc
// @Summary      Catat akses aplikasi
// @Description  Mencatat log aktivitas akses pengguna ke aplikasi
// @Tags         Apps
// @Produce      json
// @Security     BearerAuth
// @Param        slug  path      string  true  "Slug aplikasi"
// @Success      200   {object}  MessageResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /auth/apps/{slug}/log-access [post]
func (h *AuthHandler) LogAppAccess(c *fiber.Ctx) error {
	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}

	if err := h.svc.LogAppAccess(middleware.GetUserID(c), c.Params("slug"), userAgent, c.IP()); err != nil {
		return handleErr(c, err, "Gagal mencatat aktivitas")
	}
	return c.JSON(fiber.Map{"message": "Activity logged"})
}

// ──────────────────────────────────────────────────
// GET /auth/recent-activity
// ──────────────────────────────────────────────────

// GetRecentActivity godoc
// @Summary      Aktivitas terbaru
// @Description  Mengembalikan log aktivitas terbaru pengguna lintas aplikasi
// @Tags         Apps
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  []map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/recent-activity [get]
func (h *AuthHandler) GetRecentActivity(c *fiber.Ctx) error {
	activities, err := h.svc.GetRecentActivity(middleware.GetUserID(c))
	if err != nil {
		return handleErr(c, err, "Gagal mengambil recent activity")
	}
	return c.JSON(activities)
}