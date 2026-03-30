package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

func newUUID() string {
	return uuid.New().String()
}

// ──────────────────────────────────────────────────
// 1. User
// ──────────────────────────────────────────────────

type User struct {
	ID         string    `gorm:"type:varchar(36);primaryKey"                json:"id"`
	Name       string    `gorm:"type:varchar(255);not null"                 json:"name"`
	Email      string    `gorm:"type:varchar(255);uniqueIndex;not null"     json:"email"`
	Phone      *string   `                                                  json:"phone"`
	IsVerified bool      `gorm:"column:is_verified;default:false"           json:"is_verified"`
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime"           json:"created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at;autoUpdateTime"           json:"updated_at"`
}

func (u *User) BeforeCreate(_ *gorm.DB) error {
	if u.ID == "" {
		u.ID = newUUID()
	}
	return nil
}

func (User) TableName() string { return "users" }

// ──────────────────────────────────────────────────
// 2. OtpStore
// ──────────────────────────────────────────────────

type OtpStore struct {
	ID              string    `gorm:"type:varchar(36);primaryKey"              json:"id"`
	Email           string    `gorm:"type:varchar(255);uniqueIndex;not null"   json:"email"`
	OtpHash         string    `gorm:"column:otp_hash;not null"                 json:"-"`
	ExpiresAt       time.Time `gorm:"column:expires_at;not null"               json:"expires_at"`
	Attempts        int       `gorm:"default:0"                                json:"attempts"`
	LastRequestedAt time.Time `gorm:"column:last_requested_at;autoCreateTime"  json:"last_requested_at"`
	CreatedAt       time.Time `gorm:"column:created_at;autoCreateTime"         json:"created_at"`
}

func (o *OtpStore) BeforeCreate(_ *gorm.DB) error {
	if o.ID == "" {
		o.ID = newUUID()
	}
	return nil
}

func (OtpStore) TableName() string { return "otp_store" }

// ──────────────────────────────────────────────────
// 3. Session
// ──────────────────────────────────────────────────

type Session struct {
	ID             string    `gorm:"type:varchar(36);primaryKey"                    json:"id"`
	UserID         string    `gorm:"type:varchar(36);column:user_id;not null;index"  json:"user_id"`
	TokenHash      string    `gorm:"column:token_hash;type:varchar(512)"            json:"-"`
	DeviceName     *string   `gorm:"column:device_name"                             json:"device_name"`
	DeviceType     *string   `gorm:"column:device_type"                             json:"device_type"`
	IPAddress      *string   `gorm:"column:ip_address"                              json:"ip_address"`
	Location       *string   `                                                      json:"location"`
	IsActive       bool      `gorm:"column:is_active;default:true;index"            json:"is_active"`
	ExpiresAt      time.Time `gorm:"column:expires_at"                              json:"expires_at"`
	LastActivityAt time.Time `gorm:"column:last_activity_at;autoCreateTime"         json:"last_activity_at"`
	CreatedAt      time.Time `gorm:"column:created_at;autoCreateTime"               json:"created_at"`
}

func (s *Session) BeforeCreate(_ *gorm.DB) error {
	if s.ID == "" {
		s.ID = newUUID()
	}
	return nil
}

func (Session) TableName() string { return "sessions" }

// ──────────────────────────────────────────────────
// 4. LoginAlert
// ──────────────────────────────────────────────────

type AlertStatus string

const (
	AlertSuccess AlertStatus = "SUCCESS"
	AlertWarning AlertStatus = "WARNING"
	AlertFailed  AlertStatus = "FAILED"
)

type LoginAlert struct {
	ID         string      `gorm:"type:varchar(36);primaryKey"                        json:"id"`
	UserID     string      `gorm:"type:varchar(36);column:user_id;not null;index"     json:"user_id"`
	SessionID  *string     `gorm:"type:varchar(36);column:session_id"                 json:"session_id"`
	DeviceName *string     `gorm:"column:device_name"                                 json:"device_name"`
	Location   *string     `                                                          json:"location"`
	Status     AlertStatus `gorm:"type:enum('SUCCESS','WARNING','FAILED');default:'SUCCESS'" json:"status"`
	IsRead     bool        `gorm:"column:is_read;default:false;index"                 json:"is_read"`
	CreatedAt  time.Time   `gorm:"column:created_at;autoCreateTime"                   json:"created_at"`
}

func (l *LoginAlert) BeforeCreate(_ *gorm.DB) error {
	if l.ID == "" {
		l.ID = newUUID()
	}
	return nil
}

func (LoginAlert) TableName() string { return "login_alerts" }

// ──────────────────────────────────────────────────
// 5. DeleteToken
// ──────────────────────────────────────────────────

type DeleteToken struct {
	ID        string    `gorm:"type:varchar(36);primaryKey"                    json:"id"`
	UserID    string    `gorm:"type:varchar(36);column:user_id;uniqueIndex"    json:"user_id"`
	Token     string    `gorm:"type:varchar(255);uniqueIndex"                  json:"token"`
	ExpiresAt time.Time `gorm:"column:expires_at"                              json:"expires_at"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"               json:"created_at"`
}

func (d *DeleteToken) BeforeCreate(_ *gorm.DB) error {
	if d.ID == "" {
		d.ID = newUUID()
	}
	return nil
}

func (DeleteToken) TableName() string { return "delete_tokens" }

// ──────────────────────────────────────────────────
// 6. ConnectedApp
// ──────────────────────────────────────────────────

type ConnectedApp struct {
	ID          string    `gorm:"type:varchar(36);primaryKey"            json:"id"`
	Name        string    `gorm:"type:varchar(255);not null"             json:"name"`
	Slug        string    `gorm:"type:varchar(255);uniqueIndex;not null" json:"slug"`
	Icon        *string   `                                              json:"icon"`
	URL         *string   `gorm:"column:url"                             json:"url"`
	Description *string   `gorm:"type:text"                              json:"description"`
	Category    *string   `                                              json:"category"`
	IsActive    bool      `gorm:"column:is_active;default:true"          json:"is_active"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime"       json:"created_at"`
}

func (c *ConnectedApp) BeforeCreate(_ *gorm.DB) error {
	if c.ID == "" {
		c.ID = newUUID()
	}
	return nil
}

func (ConnectedApp) TableName() string { return "connected_apps" }

// ──────────────────────────────────────────────────
// 7. AppActivityLog
// ──────────────────────────────────────────────────

type AppActivityLog struct {
	ID         string       `gorm:"type:varchar(36);primaryKey"                   json:"id"`
	UserID     string       `gorm:"type:varchar(36);column:user_id;not null;index" json:"user_id"`
	AppID      string       `gorm:"type:varchar(36);column:app_id;not null;index"  json:"app_id"`
	DeviceName *string      `gorm:"column:device_name"                            json:"device_name"`
	Location   *string      `                                                     json:"location"`
	IPAddress  *string      `gorm:"column:ip_address"                             json:"ip_address"`
	CreatedAt  time.Time    `gorm:"column:created_at;autoCreateTime"              json:"created_at"`
	App        ConnectedApp `gorm:"foreignKey:AppID"                              json:"app,omitempty"`
}

func (a *AppActivityLog) BeforeCreate(_ *gorm.DB) error {
	if a.ID == "" {
		a.ID = newUUID()
	}
	return nil
}

func (AppActivityLog) TableName() string { return "app_activity_logs" }

// ──────────────────────────────────────────────────
// 8. UserAppAccess
// ──────────────────────────────────────────────────

type UserAppAccess struct {
	ID        string       `gorm:"type:varchar(36);primaryKey"                                        json:"id"`
	UserID    string       `gorm:"type:varchar(36);column:user_id;not null;index;uniqueIndex:idx_user_app" json:"user_id"`
	AppID     string       `gorm:"type:varchar(36);column:app_id;not null;uniqueIndex:idx_user_app"   json:"app_id"`
	GrantedAt time.Time    `gorm:"column:granted_at;autoCreateTime"                                   json:"granted_at"`
	IsActive  bool         `gorm:"column:is_active;default:true"                                      json:"is_active"`
	App       ConnectedApp `gorm:"foreignKey:AppID"                                                   json:"app,omitempty"`
}

func (u *UserAppAccess) BeforeCreate(_ *gorm.DB) error {
	if u.ID == "" {
		u.ID = newUUID()
	}
	return nil
}

func (UserAppAccess) TableName() string { return "user_app_access" }
