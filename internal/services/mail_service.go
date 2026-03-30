package services

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"mime"
	"net/smtp"
	"os"
	"strconv"
	"time"
)

func sendMail(to, subject, htmlBody string) error {
	host := os.Getenv("SMTP_HOST")
	portStr := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")

	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 465
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Buat raw email
	fromEncoded := mime.QEncoding.Encode("utf-8", "BOMA SSO")
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromEncoded, user))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", to))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject)))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("\r\n")
	buf.WriteString(htmlBody)

	tlsCfg := &tls.Config{ServerName: host}
	auth := smtp.PlainAuth("", user, pass, host)

	if port == 465 {
		// Port 465: implicit TLS
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("dial TLS: %w", err)
		}
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("smtp client: %w", err)
		}
		defer c.Quit()
		return smtpSend(c, auth, user, to, buf.Bytes())
	}

	// Port 587: STARTTLS
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer c.Quit()
	if err := c.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	return smtpSend(c, auth, user, to, buf.Bytes())
}

func smtpSend(c *smtp.Client, auth smtp.Auth, from, to string, msg []byte) error {
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return w.Close()
}

func SendOtpEmail(to, otp string) error {
	body := fmt.Sprintf(`
		<div style="font-family:sans-serif;max-width:400px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:8px">
			<h2 style="color:#103B74;margin-bottom:8px">Kode Verifikasi BOMA SSO</h2>
			<p>Gunakan kode OTP berikut untuk masuk:</p>
			<div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#103B74;margin:16px 0">%s</div>
			<p style="color:#666;font-size:13px">Kode berlaku selama <strong>5 menit</strong>.<br/>Jangan bagikan kode ini kepada siapapun.</p>
		</div>
	`, otp)
	return sendMail(to, "Kode OTP Login - BOMA SSO", body)
}

func SendDeleteConfirmationEmail(to, name, confirmURL string) error {
	body := fmt.Sprintf(`
		<div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;border:1px solid #e0e0e0;border-radius:10px">
			<h2 style="color:#103B74;margin-bottom:8px">Permintaan Penghapusan Akun</h2>
			<p style="color:#374151">Halo <strong>%s</strong>,</p>
			<p style="color:#374151">Kami menerima permintaan untuk menghapus akun BOMA Anda secara permanen.</p>
			<p style="color:#374151">Jika Anda memang ingin menghapus akun, klik tombol di bawah. Link berlaku <strong>15 menit</strong>.</p>
			<div style="text-align:center;margin:28px 0">
				<a href="%s" style="background-color:#b91c1c;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;display:inline-block">
					Konfirmasi Hapus Akun
				</a>
			</div>
			<p style="color:#6b7280;font-size:13px">Jika Anda tidak meminta ini, abaikan email ini.</p>
			<hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0"/>
			<p style="color:#9ca3af;font-size:12px;text-align:center">© BOMA SSO | All Rights Reserved</p>
		</div>
	`, name, confirmURL)
	return sendMail(to, "Konfirmasi Penghapusan Akun BOMA", body)
}