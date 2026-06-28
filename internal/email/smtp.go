package email

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPSender struct {
	host        string
	port        int
	from        string
	frontendURL string
}

func NewSMTPSender(host string, port int, from, frontendURL string) *SMTPSender {
	return &SMTPSender{host: host, port: port, from: from, frontendURL: frontendURL}
}

func (s *SMTPSender) SendVerification(_ context.Context, to, token string) error {
	subject := "Verify your email"
	link := fmt.Sprintf("%s/verify-email?token=%s", s.frontendURL, token)
	body := fmt.Sprintf("Please verify your email by clicking the link below:\n\n%s", link)
	return s.send(to, subject, body)
}

func (s *SMTPSender) SendPasswordReset(_ context.Context, to, token string) error {
	subject := "Password reset"
	link := fmt.Sprintf("%s/reset-password?token=%s", s.frontendURL, token)
	body := fmt.Sprintf("To reset your password, click the link below:\n\n%s", link)
	return s.send(to, subject, body)
}

func (s *SMTPSender) send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		s.from, to, subject, body)

	return smtp.SendMail(addr, nil, s.from, []string{to}, []byte(msg))
}
