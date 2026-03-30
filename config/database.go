package config

import (
	"log"
	"os"
	"sync"

	"dashboard-sso/internal/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	db   *gorm.DB
	once sync.Once
)

func GetDB() *gorm.DB {
	once.Do(func() {
		dsn := os.Getenv("DATABASE_URL")
		if dsn == "" {
			log.Fatal("DATABASE_URL tidak ditemukan di environment")
		}

		var err error
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
		if err != nil {
			log.Fatalf("Gagal koneksi ke database: %v", err)
		}

		// Nonaktifkan FK checks sementara agar AutoMigrate bisa memodifikasi index
		db.Exec("SET FOREIGN_KEY_CHECKS=0")
		if err := db.AutoMigrate(
			&models.User{},
			&models.OtpStore{},
			&models.Session{},
			&models.LoginAlert{},
			&models.DeleteToken{},
			&models.ConnectedApp{},
			&models.AppActivityLog{},
			&models.UserAppAccess{},
		); err != nil {
			db.Exec("SET FOREIGN_KEY_CHECKS=1")
			log.Fatalf("AutoMigrate gagal: %v", err)
		}
		db.Exec("SET FOREIGN_KEY_CHECKS=1")

		log.Println("Database terkoneksi dan schema up-to-date")
	})
	return db
}