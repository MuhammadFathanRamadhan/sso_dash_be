package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"dashboard-sso/internal/models"
	"dashboard-sso/internal/repositories"
	"dashboard-sso/internal/utils"

	"github.com/avct/uasurfer"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ──────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────

type AppError struct {
	Status  int
	Message string
}

func (e *AppError) Error() string { return e.Message }

func appErr(status int, msg string) *AppError {
	return &AppError{Status: status, Message: msg}
}

// ──────────────────────────────────────────────────
// Device Info (dari UA string atau native app)
// ──────────────────────────────────────────────────

type DeviceInfo struct {
	DeviceName string `json:"deviceName"`
	DeviceType string `json:"deviceType"`
	OsName     string `json:"osName"`
	OsVersion  string `json:"osVersion"`
}

func resolveDeviceInfo(userAgent string, deviceInfo *DeviceInfo) (name, devType string) {
	if deviceInfo != nil && deviceInfo.DeviceName != "" {
		os := ""
		if deviceInfo.OsName != "" {
			os = " / " + deviceInfo.OsName
			if deviceInfo.OsVersion != "" {
				os += " " + deviceInfo.OsVersion
			}
		}
		full := deviceInfo.DeviceName + os
		if len(full) > 100 {
			full = full[:100]
		}
		dt := deviceInfo.DeviceType
		if dt == "" {
			dt = "Unknown"
		}
		return full, dt
	}

	// Parse User-Agent
	ua := uasurfer.Parse(userAgent)

	browserName := ua.Browser.Name.StringTrimPrefix()
	osName := ua.OS.Name.StringTrimPrefix()

	var dt string
	switch ua.DeviceType {
	case uasurfer.DevicePhone:
		dt = "Phone"
	case uasurfer.DeviceTablet:
		dt = "Tablet"
	default:
		dt = "Desktop"
	}

	full := browserName + " / " + osName
	if len(full) > 100 {
		full = full[:100]
	}
	return full, dt
}

// ──────────────────────────────────────────────────
// AuthService
// ──────────────────────────────────────────────────

type AuthService struct {
	db          *gorm.DB
	userRepo    *repositories.UserRepository
	delTokenRepo *repositories.DeleteTokenRepository
	otpSvc      *OtpService
}

func NewAuthService(
	db *gorm.DB,
	userRepo *repositories.UserRepository,
	delTokenRepo *repositories.DeleteTokenRepository,
	otpSvc *OtpService,
) *AuthService {
	return &AuthService{
		db:           db,
		userRepo:     userRepo,
		delTokenRepo: delTokenRepo,
		otpSvc:       otpSvc,
	}
}

// ──────────────────────────────────────────────────
// Register
// ──────────────────────────────────────────────────

type RegisterResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (s *AuthService) Register(name, email, phone string) (*RegisterResponse, error) {
	if name == "" || email == "" || phone == "" {
		return nil, appErr(400, "Semua kolom wajib diisi")
	}
	if !utils.IsValidEmail(email) {
		return nil, appErr(400, "Format email tidak valid")
	}
	if !utils.IsValidPhone(phone) {
		return nil, appErr(400, "Nomor telepon tidak valid (8-15 digit)")
	}

	existing, err := s.userRepo.FindByEmail(email)
	if err == nil {
		if existing.IsVerified {
			return nil, appErr(409, "Email sudah terdaftar")
		}
		// User ada tapi belum verified → update data & kirim ulang OTP
		s.db.Model(existing).Updates(map[string]interface{}{
			"name":  name,
			"phone": &phone,
		})
		otpCode, err := s.otpSvc.CreateOtp(email)
		if err != nil {
			return nil, err
		}
		go SendRegisterOtpEmail(email, otpCode)
		return &RegisterResponse{ID: existing.ID, Name: name, Email: email}, nil
	}

	user, err := s.userRepo.CreateUser(name, email, phone)
	if err != nil {
		return nil, err
	}

	// Kirim OTP untuk verifikasi email
	otpCode, err := s.otpSvc.CreateOtp(email)
	if err != nil {
		return nil, err
	}
	go SendRegisterOtpEmail(email, otpCode)

	go s.autoConnectBomaSSO(user.ID)

	return &RegisterResponse{ID: user.ID, Name: user.Name, Email: user.Email}, nil
}

// ──────────────────────────────────────────────────
// Verify Register OTP
// ──────────────────────────────────────────────────

func (s *AuthService) VerifyRegisterOtp(email, otp string) error {
	if email == "" || otp == "" {
		return appErr(400, "Email dan OTP wajib diisi")
	}

	result := s.otpSvc.VerifyOtp(email, otp)
	if !result.OK {
		return appErr(result.Status, result.Message)
	}

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return appErr(404, "User tidak ditemukan")
	}

	return s.db.Model(user).Update("is_verified", true).Error
}

// ──────────────────────────────────────────────────
// Resend Register OTP
// ──────────────────────────────────────────────────

func (s *AuthService) ResendRegisterOtp(email string) error {
	if email == "" {
		return appErr(400, "Email wajib diisi")
	}

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return appErr(404, "Email tidak ditemukan")
	}
	if user.IsVerified {
		return appErr(400, "Email sudah terverifikasi")
	}

	existing, _ := s.otpSvc.GetOtpData(email)
	if !CanRequestOtp(existing) {
		return appErr(429, "Silakan tunggu 1 menit sebelum minta OTP baru")
	}

	otpCode, err := s.otpSvc.CreateOtp(email)
	if err != nil {
		return err
	}

	return SendRegisterOtpEmail(email, otpCode)
}

// ──────────────────────────────────────────────────
// Request OTP
// ──────────────────────────────────────────────────

type UserPreview struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (s *AuthService) RequestOtp(email string) (*UserPreview, error) {
	if email == "" {
		return nil, appErr(400, "Email wajib diisi")
	}

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, appErr(404, "Email belum terdaftar. Silakan buat akun terlebih dahulu.")
	}
	if !user.IsVerified {
		return nil, appErr(403, "Email belum diverifikasi. Silakan verifikasi email Anda terlebih dahulu.")
	}

	existing, _ := s.otpSvc.GetOtpData(email)
	if !CanRequestOtp(existing) {
		return nil, appErr(429, "Silakan tunggu 1 menit sebelum minta OTP baru")
	}

	otpCode, err := s.otpSvc.CreateOtp(email)
	if err != nil {
		return nil, err
	}

	if err := SendOtpEmail(email, otpCode); err != nil {
		return nil, fmt.Errorf("gagal kirim OTP: %w", err)
	}

	phone := ""
	if user.Phone != nil {
		phone = *user.Phone
	}
	return &UserPreview{Name: user.Name, Email: user.Email, Phone: phone}, nil
}

// ──────────────────────────────────────────────────
// Verify OTP
// ──────────────────────────────────────────────────

type VerifyOtpRequest struct {
	Email      string      `json:"email"`
	Otp        string      `json:"otp"`
	DeviceInfo *DeviceInfo `json:"deviceInfo"`
}

type VerifyOtpResponse struct {
	Token string      `json:"token"`
	User  UserPreview `json:"user"`
}

func (s *AuthService) VerifyOtp(req VerifyOtpRequest, userAgent, ipAddress string) (*VerifyOtpResponse, error) {
	result := s.otpSvc.VerifyOtp(req.Email, req.Otp)
	if !result.OK {
		return nil, appErr(result.Status, result.Message)
	}

	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, appErr(404, "User tidak ditemukan")
	}

	deviceName, deviceType := resolveDeviceInfo(userAgent, req.DeviceInfo)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	location := ResolveLocation(ipAddress)

	// Buat session dulu agar sessionId bisa disertakan di JWT
	session := &models.Session{
		UserID:     user.ID,
		TokenHash:  "",
		DeviceName: strPtr(deviceName),
		DeviceType: strPtr(deviceType),
		IPAddress:  strPtr(ipAddress),
		Location:   strPtr(location),
		ExpiresAt:  expiresAt,
	}
	if err := s.db.Create(session).Error; err != nil {
		return nil, err
	}

	// Buat JWT dengan sessionId
	claims := jwt.MapClaims{
		"userId":    user.ID,
		"email":     user.Email,
		"name":      user.Name,
		"sessionId": session.ID,
		"exp":       time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenObj.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return nil, err
	}

	// Update tokenHash setelah token dibuat
	suffix := tokenStr
	if len(suffix) > 30 {
		suffix = suffix[len(suffix)-30:]
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(suffix), bcrypt.DefaultCost)
	s.db.Model(session).Update("token_hash", string(hash))

	// Buat login alert
	s.db.Create(&models.LoginAlert{
		UserID:     user.ID,
		SessionID:  strPtr(session.ID),
		DeviceName: strPtr(deviceName),
		Location:   strPtr(location),
		Status:     models.AlertSuccess,
	})

	// Auto-connect BOMA SSO & log activity (non-blocking)
	go s.autoConnectBomaSSO(user.ID)
	go s.logBomaActivity(user.ID, deviceName, location, ipAddress)

	phone := ""
	if user.Phone != nil {
		phone = *user.Phone
	}
	return &VerifyOtpResponse{
		Token: tokenStr,
		User:  UserPreview{Name: user.Name, Email: user.Email, Phone: phone},
	}, nil
}

// ──────────────────────────────────────────────────
// Get Me
// ──────────────────────────────────────────────────

type UserProfile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (s *AuthService) GetMe(userID string) (*UserProfile, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, appErr(404, "User tidak ditemukan")
	}
	phone := ""
	if user.Phone != nil {
		phone = *user.Phone
	}
	return &UserProfile{ID: user.ID, Name: user.Name, Email: user.Email, Phone: phone}, nil
}

// ──────────────────────────────────────────────────
// Stats
// ──────────────────────────────────────────────────

type StatsResponse struct {
	TotalLogins    int64 `json:"totalLogins"`
	ActiveSessions int64 `json:"activeSessions"`
	SavedApps      int64 `json:"savedApps"`
}

func (s *AuthService) GetStats(userID string) (*StatsResponse, error) {
	var totalLogins, activeSessions, savedApps int64
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		s.db.Model(&models.LoginAlert{}).
			Where("user_id = ? AND status = ?", userID, "SUCCESS").
			Count(&totalLogins)
	}()
	go func() {
		defer wg.Done()
		s.db.Model(&models.Session{}).
			Where("user_id = ? AND is_active = ? AND expires_at > ?", userID, true, time.Now()).
			Count(&activeSessions)
	}()
	go func() {
		defer wg.Done()
		s.db.Model(&models.UserAppAccess{}).
			Where("user_id = ? AND is_active = ?", userID, true).
			Count(&savedApps)
	}()

	wg.Wait()
	return &StatsResponse{
		TotalLogins:    totalLogins,
		ActiveSessions: activeSessions,
		SavedApps:      savedApps,
	}, nil
}

// ──────────────────────────────────────────────────
// Logout
// ──────────────────────────────────────────────────

func (s *AuthService) Logout(userID, sessionID string) error {
	if sessionID != "" {
		return s.db.Model(&models.Session{}).
			Where("id = ? AND user_id = ?", sessionID, userID).
			Update("is_active", false).Error
	}
	// Fallback token lama tanpa sessionId: logout semua session
	return s.db.Model(&models.Session{}).
		Where("user_id = ? AND is_active = ?", userID, true).
		Update("is_active", false).Error
}

// ──────────────────────────────────────────────────
// Logout Session (specific device)
// ──────────────────────────────────────────────────

func (s *AuthService) LogoutSession(userID, targetSessionID string) error {
	var session models.Session
	if err := s.db.Where("id = ? AND user_id = ?", targetSessionID, userID).First(&session).Error; err != nil {
		return appErr(404, "Session tidak ditemukan")
	}
	return s.db.Model(&session).Update("is_active", false).Error
}

// ──────────────────────────────────────────────────
// Logout Others
// ──────────────────────────────────────────────────

func (s *AuthService) LogoutOthers(userID, sessionID, rawToken string) error {
	currentSessionID := sessionID

	// Fallback token lama (tanpa sessionId): cocokkan via tokenHash
	if currentSessionID == "" && rawToken != "" {
		var sessions []models.Session
		s.db.Where("user_id = ? AND is_active = ?", userID, true).
			Select("id, token_hash").
			Find(&sessions)

		suffix := rawToken
		if len(suffix) > 30 {
			suffix = suffix[len(suffix)-30:]
		}
		for _, sess := range sessions {
			if sess.TokenHash != "" {
				if err := bcrypt.CompareHashAndPassword([]byte(sess.TokenHash), []byte(suffix)); err == nil {
					currentSessionID = sess.ID
					break
				}
			}
		}
	}

	if currentSessionID == "" {
		return appErr(400, "Session tidak teridentifikasi. Silakan login ulang.")
	}

	return s.db.Model(&models.Session{}).
		Where("user_id = ? AND is_active = ? AND id != ?", userID, true, currentSessionID).
		Update("is_active", false).Error
}

// ──────────────────────────────────────────────────
// Get Sessions
// ──────────────────────────────────────────────────

type SessionInfo struct {
	ID         string    `json:"id"`
	DeviceName *string   `json:"device_name"`
	DeviceType *string   `json:"device_type"`
	IPAddress  *string   `json:"ip_address"`
	IsActive   bool      `json:"is_active"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *AuthService) GetSessions(userID string) ([]SessionInfo, error) {
	var sessions []models.Session
	err := s.db.Where("user_id = ? AND is_active = ? AND expires_at > ?", userID, true, time.Now()).
		Order("created_at DESC").
		Limit(20).
		Select("id, device_name, device_type, ip_address, is_active, expires_at, created_at").
		Find(&sessions).Error
	if err != nil {
		return nil, err
	}

	result := make([]SessionInfo, len(sessions))
	for i, s := range sessions {
		result[i] = SessionInfo{
			ID:         s.ID,
			DeviceName: s.DeviceName,
			DeviceType: s.DeviceType,
			IPAddress:  s.IPAddress,
			IsActive:   s.IsActive,
			ExpiresAt:  s.ExpiresAt,
			CreatedAt:  s.CreatedAt,
		}
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Alerts
// ──────────────────────────────────────────────────

type AlertInfo struct {
	ID         string            `json:"id"`
	DeviceName *string           `json:"device_name"`
	Location   *string           `json:"location"`
	Status     models.AlertStatus `json:"status"`
	IsRead     bool              `json:"is_read"`
	CreatedAt  time.Time         `json:"created_at"`
}

func (s *AuthService) GetAlerts(userID string) ([]AlertInfo, error) {
	var alerts []models.LoginAlert
	err := s.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(50).
		Select("id, device_name, location, status, is_read, created_at").
		Find(&alerts).Error
	if err != nil {
		return nil, err
	}

	result := make([]AlertInfo, len(alerts))
	for i, a := range alerts {
		result[i] = AlertInfo{
			ID:         a.ID,
			DeviceName: a.DeviceName,
			Location:   a.Location,
			Status:     a.Status,
			IsRead:     a.IsRead,
			CreatedAt:  a.CreatedAt,
		}
	}
	return result, nil
}

func (s *AuthService) MarkAlertRead(userID, alertID string) error {
	return s.db.Model(&models.LoginAlert{}).
		Where("id = ? AND user_id = ?", alertID, userID).
		Update("is_read", true).Error
}

func (s *AuthService) ClearAlerts(userID string) error {
	return s.db.Model(&models.LoginAlert{}).
		Where("user_id = ?", userID).
		Update("is_read", true).Error
}

// ──────────────────────────────────────────────────
// Account Deletion
// ──────────────────────────────────────────────────

func (s *AuthService) RequestAccountDeletion(userID string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return appErr(404, "User tidak ditemukan")
	}

	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	expiresAt := time.Now().Add(15 * time.Minute)

	if err := s.delTokenRepo.UpsertToken(userID, token, expiresAt); err != nil {
		return err
	}

	confirmURL := fmt.Sprintf("%s/auth/confirm-delete?token=%s", os.Getenv("APP_URL"), token)
	return SendDeleteConfirmationEmail(user.Email, user.Name, confirmURL)
}

func (s *AuthService) ConfirmAccountDeletion(token string) error {
	if token == "" {
		return appErr(400, "Token tidak ditemukan")
	}

	record, err := s.delTokenRepo.FindByToken(token)
	if err != nil {
		return appErr(400, "Link tidak valid atau sudah digunakan")
	}

	if time.Now().After(record.ExpiresAt) {
		s.delTokenRepo.DeleteByToken(token)
		return appErr(400, "Link sudah kadaluarsa")
	}

	return s.userRepo.DeleteByID(record.UserID)
}

// ──────────────────────────────────────────────────
// Apps
// ──────────────────────────────────────────────────

type AppDetail struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	Icon        *string `json:"icon"`
	URL         *string `json:"url"`
	Description *string `json:"description"`
	Category    *string `json:"category"`
}

type UserAppItem struct {
	ID        string    `json:"id"`
	GrantedAt time.Time `json:"granted_at"`
	App       AppDetail `json:"app"`
}

func (s *AuthService) GetUserApps(userID string) ([]UserAppItem, error) {
	var accesses []models.UserAppAccess
	err := s.db.Where("user_id = ? AND is_active = ?", userID, true).
		Order("granted_at DESC").
		Preload("App").
		Find(&accesses).Error
	if err != nil {
		return nil, err
	}

	result := make([]UserAppItem, len(accesses))
	for i, a := range accesses {
		result[i] = UserAppItem{
			ID:        a.ID,
			GrantedAt: a.GrantedAt,
			App: AppDetail{
				ID:          a.App.ID,
				Name:        a.App.Name,
				Slug:        a.App.Slug,
				Icon:        a.App.Icon,
				URL:         a.App.URL,
				Description: a.App.Description,
				Category:    a.App.Category,
			},
		}
	}
	return result, nil
}

func (s *AuthService) ConnectApp(userID, appSlug string) (string, *AppDetail, error) {
	if appSlug == "" {
		return "", nil, appErr(400, "App slug wajib diisi")
	}

	var app models.ConnectedApp
	if err := s.db.Where("slug = ?", appSlug).First(&app).Error; err != nil {
		return "", nil, appErr(404, "Aplikasi tidak ditemukan")
	}
	if !app.IsActive {
		return "", nil, appErr(400, "Aplikasi sedang tidak aktif")
	}

	appDetail := &AppDetail{
		ID: app.ID, Name: app.Name, Slug: app.Slug,
		Icon: app.Icon, URL: app.URL, Description: app.Description, Category: app.Category,
	}

	var existing models.UserAppAccess
	err := s.db.Where("user_id = ? AND app_id = ?", userID, app.ID).First(&existing).Error

	if err == nil {
		// Record exists
		if existing.IsActive {
			return "Aplikasi sudah terhubung", appDetail, nil
		}
		s.db.Model(&existing).Updates(map[string]interface{}{
			"is_active":  true,
			"granted_at": time.Now(),
		})
		return "Aplikasi berhasil dihubungkan kembali", appDetail, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil, err
	}

	s.db.Create(&models.UserAppAccess{UserID: userID, AppID: app.ID})
	return "Aplikasi berhasil dihubungkan", appDetail, nil
}

func (s *AuthService) DisconnectApp(userID, appSlug string) error {
	if appSlug == "" {
		return appErr(400, "App slug wajib diisi")
	}

	var app models.ConnectedApp
	if err := s.db.Where("slug = ?", appSlug).First(&app).Error; err != nil {
		return appErr(404, "Aplikasi tidak ditemukan")
	}

	var access models.UserAppAccess
	if err := s.db.Where("user_id = ? AND app_id = ?", userID, app.ID).First(&access).Error; err != nil {
		return appErr(400, "Aplikasi tidak terhubung")
	}
	if !access.IsActive {
		return appErr(400, "Aplikasi tidak terhubung")
	}

	return s.db.Model(&access).Update("is_active", false).Error
}

// ──────────────────────────────────────────────────
// App Activity
// ──────────────────────────────────────────────────

func (s *AuthService) LogAppAccess(userID, appSlug, userAgent, ipAddress string) error {
	var app models.ConnectedApp
	if err := s.db.Where("slug = ?", appSlug).First(&app).Error; err != nil {
		return appErr(404, "Aplikasi tidak ditemukan")
	}

	deviceName, _ := resolveDeviceInfo(userAgent, nil)
	location := ResolveLocation(ipAddress)

	return s.db.Create(&models.AppActivityLog{
		UserID:     userID,
		AppID:      app.ID,
		DeviceName: strPtr(deviceName),
		Location:   strPtr(location),
		IPAddress:  strPtr(ipAddress),
	}).Error
}

type ActivityItem struct {
	ID         string    `json:"id"`
	DeviceName *string   `json:"device_name"`
	Location   *string   `json:"location"`
	IPAddress  *string   `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
	App        struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"app"`
}

func (s *AuthService) GetRecentActivity(userID string) ([]ActivityItem, error) {
	var logs []models.AppActivityLog
	err := s.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(4).
		Preload("App").
		Find(&logs).Error
	if err != nil {
		return nil, err
	}

	result := make([]ActivityItem, len(logs))
	for i, l := range logs {
		result[i] = ActivityItem{
			ID:         l.ID,
			DeviceName: l.DeviceName,
			Location:   l.Location,
			IPAddress:  l.IPAddress,
			CreatedAt:  l.CreatedAt,
		}
		result[i].App.Name = l.App.Name
		result[i].App.Slug = l.App.Slug
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────

func (s *AuthService) autoConnectBomaSSO(userID string) {
	var app models.ConnectedApp
	if err := s.db.Where("slug = ?", "boma-sso").First(&app).Error; err != nil {
		return
	}

	access := models.UserAppAccess{UserID: userID, AppID: app.ID}
	s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "app_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"is_active"}),
	}).Create(&access)
}

func (s *AuthService) logBomaActivity(userID, deviceName, location, ipAddress string) {
	var app models.ConnectedApp
	if err := s.db.Where("slug = ?", "boma-sso").First(&app).Error; err != nil {
		return
	}
	s.db.Create(&models.AppActivityLog{
		UserID:     userID,
		AppID:      app.ID,
		DeviceName: strPtr(deviceName),
		Location:   strPtr(location),
		IPAddress:  strPtr(ipAddress),
	})
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
