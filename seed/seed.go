// Seed database dengan 12 aplikasi BOMA.
// Jalankan: jangan lupa go run seed/seed.go
package main

import (
	"fmt"
	"log"

	"dashboard-sso/config"
	"dashboard-sso/internal/models"

	"github.com/joho/godotenv"
	"gorm.io/gorm/clause"
)

type appSeed struct {
	Name        string
	Slug        string
	Icon        string
	Category    string
	Description string
}

var apps = []appSeed{
	{"BOMA SSO", "boma-sso", "🔐", "Website SSO", "Sistem Single Sign-On terpusat untuk seluruh aplikasi BOMA."},
	{"Rencana Anggaran Biaya", "rab", "📋", "Manajemen", "Platform manajemen proyek dan kolaborasi tim."},
	{"Estimasi Sebelum Gambar", "esg", "🎨", "Manajemen", "Alat perencanaan dan estimasi proyek konstruksi."},
	{"Administrasi Proyekita", "adm", "💰", "Manajemen", "Dashboard keuangan dan laporan akuntansi."},
	{"Fashion Bareng", "fb", "🐄", "Agrikultur", "Aplikasi manajemen peternakan dan agribisnis."},
	{"Petfood Bareng", "pf", "🍖", "Penjualan", "Aplikasi penjualan produk makanan hewan."},
	{"Bengkel Bareng", "bb", "🔧", "Manajemen", "Platform manajemen bengkel dan layanan teknis."},
	{"Belanja Rumahan Bareng", "brb", "💳", "Penjualan", "Aplikasi e-commerce untuk kebutuhan rumah tangga."},
	{"Ternak Bareng", "tb", "📦", "Penjualan", "Aplikasi penjualan produk ternak."},
	{"Pabrik Bareng", "pb", "🏭", "Manajemen", "Platform manajemen produksi dan operasional pabrik."},
	{"Kirim Bareng", "kb", "📄", "Manajemen", "Aplikasi manajemen logistik dan pengiriman barang."},
	{"Sewa Bareng", "sb", "🎧", "Support", "Sistem manajemen penyewaan alat dan perlengkapan."},
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("File .env tidak ditemukan, menggunakan environment sistem")
	}

	db := config.GetDB()
	fmt.Println("Seeding connected apps...")

	for _, a := range apps {
		icon := a.Icon
		desc := a.Description
		cat := a.Category

		record := models.ConnectedApp{
			Name:        a.Name,
			Slug:        a.Slug,
			Icon:        &icon,
			Description: &desc,
			Category:    &cat,
			IsActive:    true,
		}

		// Upsert: insert jika belum ada, skip jika sudah ada (tidak overwrite)
		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "slug"}},
			DoNothing: true,
		}).Create(&record).Error; err != nil {
			log.Printf("Gagal seed app %s: %v\n", a.Slug, err)
			continue
		}

		fmt.Printf("  ✓ %s (%s)\n", a.Name, a.Slug)
	}

	fmt.Printf("\n%d apps berhasil di-seed.\n", len(apps))
}
