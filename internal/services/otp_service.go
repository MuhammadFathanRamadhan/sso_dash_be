package services

import (
	"fmt"
	"math/rand"
	"time"

	"dashboard-sso/internal/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type OtpService struct {
	db *gorm.DB
}

func NewOtpService(db *gorm.DB) *OtpService {
	return &OtpService{db: db}
}

func (s *OtpService) GetOtpData(email string) (*models.OtpStore, error) {
	var otp models.OtpStore
	err := s.db.Where("email = ?", email).First(&otp).Error
	if err != nil {
		return nil, err
	}
	return &otp, nil
}

// CanRequestOtp mengembalikan true jika user boleh meminta OTP baru.
// Cooldown: tidak boleh minta OTP baru jika masih < 4 menit sebelum expire
// (artinya OTP baru saja dibuat dalam 1 menit terakhir).
func CanRequestOtp(existing *models.OtpStore) bool {
	if existing == nil {
		return true
	}
	cooldownUntil := existing.ExpiresAt.Add(-4 * time.Minute)
	return time.Now().After(cooldownUntil)
}

func (s *OtpService) CreateOtp(email string) (string, error) {
	otpCode := fmt.Sprintf("%04d", 1000+rand.Intn(9000))
	hash, err := bcrypt.GenerateFromPassword([]byte(otpCode), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(5 * time.Minute)
	record := models.OtpStore{
		Email:           email,
		OtpHash:         string(hash),
		ExpiresAt:       expiresAt,
		Attempts:        0,
		LastRequestedAt: time.Now(),
	}

	err = s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "email"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"otp_hash":          string(hash),
			"expires_at":        expiresAt,
			"attempts":          0,
			"last_requested_at": time.Now(),
		}),
	}).Create(&record).Error

	return otpCode, err
}

type OtpVerifyResult struct {
	OK      bool
	Status  int
	Message string
}

func (s *OtpService) VerifyOtp(email, otp string) OtpVerifyResult {
	var data models.OtpStore
	if err := s.db.Where("email = ?", email).First(&data).Error; err != nil {
		return OtpVerifyResult{OK: false, Status: 400, Message: "OTP belum diminta / invalid"}
	}

	if time.Now().After(data.ExpiresAt) {
		s.db.Where("email = ?", email).Delete(&models.OtpStore{})
		return OtpVerifyResult{OK: false, Status: 400, Message: "OTP kadaluarsa"}
	}

	// Increment attempts
	s.db.Model(&data).UpdateColumn("attempts", gorm.Expr("attempts + 1"))
	data.Attempts++

	if data.Attempts > 5 {
		s.db.Where("email = ?", email).Delete(&models.OtpStore{})
		return OtpVerifyResult{OK: false, Status: 429, Message: "Terlalu banyak percobaan"}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(data.OtpHash), []byte(otp)); err != nil {
		return OtpVerifyResult{OK: false, Status: 400, Message: "OTP salah"}
	}

	s.db.Where("email = ?", email).Delete(&models.OtpStore{})
	return OtpVerifyResult{OK: true}
}