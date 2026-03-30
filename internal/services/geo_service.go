package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ResolveLocation mengubah IP address menjadi "Kota, Negara"
// menggunakan ip-api.com (gratis, tanpa API key, limit 45 req/menit).
// Bersifat non-blocking: jika gagal, mengembalikan string kosong.
func ResolveLocation(ip string) string {
	// Bersihkan prefix ::ffff: (IPv4-mapped IPv6)
	cleanIP := strings.TrimPrefix(ip, "::ffff:")

	if cleanIP == "" ||
		cleanIP == "::1" ||
		cleanIP == "127.0.0.1" ||
		strings.HasPrefix(cleanIP, "192.168.") ||
		strings.HasPrefix(cleanIP, "10.") ||
		strings.HasPrefix(cleanIP, "172.") {
		return "Local Network"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://ip-api.com/json/%s?fields=status,city,country", cleanIP), nil)
	if err != nil {
		return ""
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var data struct {
		Status  string `json:"status"`
		City    string `json:"city"`
		Country string `json:"country"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}

	if data.Status != "success" {
		return ""
	}

	parts := []string{}
	if data.City != "" {
		parts = append(parts, data.City)
	}
	if data.Country != "" {
		parts = append(parts, data.Country)
	}
	return strings.Join(parts, ", ")
}