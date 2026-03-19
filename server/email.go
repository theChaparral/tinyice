package server

import (
	"fmt"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	mail "github.com/wneessen/go-mail"
)

func (s *Server) notifyAdminsNewPendingUser(pending *config.PendingUser) {
	if s.Config.SMTP == nil || !s.Config.SMTP.Enabled {
		return
	}

	var adminEmails []string
	for _, user := range s.Config.Users {
		if user.Role == config.RoleSuperAdmin && len(user.LinkedEmails) > 0 {
			adminEmails = append(adminEmails, user.LinkedEmails[0])
		}
	}

	if len(adminEmails) == 0 {
		return
	}

	subject := fmt.Sprintf("[TinyIce] New access request from %s", pending.Email)
	body := fmt.Sprintf("A new user has requested access to your TinyIce server.\n\n"+
		"Name: %s\n"+
		"Email: %s\n"+
		"Provider: %s\n"+
		"Requested: %s\n\n"+
		"Log in to your admin panel to approve or deny this request.",
		pending.Name, pending.Email, pending.Provider, pending.RequestedAt)

	for _, to := range adminEmails {
		if err := s.sendEmail(to, subject, body); err != nil {
			logger.L.Warnw("Failed to send notification email", "to", to, "error", err)
		}
	}
}

func (s *Server) sendEmail(to, subject, body string) error {
	smtp := s.Config.SMTP
	if smtp == nil || !smtp.Enabled {
		return fmt.Errorf("SMTP not configured")
	}

	m := mail.NewMsg()
	if err := m.From(smtp.From); err != nil {
		return err
	}
	if err := m.To(to); err != nil {
		return err
	}
	m.Subject(subject)
	m.SetBodyString(mail.TypeTextPlain, body)

	port := smtp.Port
	if port == 0 {
		port = 587
	}

	c, err := mail.NewClient(smtp.Host,
		mail.WithPort(port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(smtp.Username),
		mail.WithPassword(smtp.Password),
		mail.WithTLSPortPolicy(mail.TLSMandatory),
	)
	if err != nil {
		return err
	}

	return c.DialAndSend(m)
}
