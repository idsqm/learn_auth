package email

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPSender struct {
	host string
	port int
	from string
}

func NewSMTPSender(host string, port int, from string) *SMTPSender {
	return &SMTPSender{host: host, port: port, from: from}
}

func (s *SMTPSender) SendVerification(_ context.Context, to, token string) error {
	subject := "Verify your email"
	body := fmt.Sprintf("Your verification code: %s", token)
	return s.send(to, subject, body)
}

func (s *SMTPSender) SendPasswordReset(_ context.Context, to, token string) error {
	subject := "Password reset"
	body := fmt.Sprintf("Your password reset code: %s", token)
	return s.send(to, subject, body)
}

func (s *SMTPSender) send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		s.from, to, subject, body)

	return smtp.SendMail(addr, nil, s.from, []string{to}, []byte(msg))
}
