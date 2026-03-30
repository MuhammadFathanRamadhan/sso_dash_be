package repositories

import (
	"time"

	"dashboard-sso/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DeleteTokenRepository struct {
	db *gorm.DB
}

func NewDeleteTokenRepository(db *gorm.DB) *DeleteTokenRepository {
	return &DeleteTokenRepository{db: db}
}

func (r *DeleteTokenRepository) UpsertToken(userID, token string, expiresAt time.Time) error {
	record := models.DeleteToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
	return r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"token", "expires_at"}),
	}).Create(&record).Error
}

func (r *DeleteTokenRepository) FindByToken(token string) (*models.DeleteToken, error) {
	var record models.DeleteToken
	err := r.db.Where("token = ?", token).First(&record).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *DeleteTokenRepository) DeleteByToken(token string) error {
	return r.db.Where("token = ?", token).Delete(&models.DeleteToken{}).Error
}