package main

import (
	"fmt"
	"io"
	"log"

	"math/rand"
	"net/mail"
	"net/smtp"

	env "github.com/caarlos0/env/v7"
	"github.com/gliderlabs/ssh"
)

type Options struct {
	Host        string `env:"SSH_HOST" envDefault:"0.0.0.0"`
	Port        int    `env:"SSH_PORT" envDefault:"22"`
	TokenLength uint   `env:"TOKEN_LENGTH" envDefault:"6"`

	SMTPServer  string `env:"MAIL_SERVER" envDefault:"localhost:25"`
	FromName    string `env:"MAIL_FROM_NAME" envDefault:"SSH-Auth"`
	FromAddress string `env:"MAIL_FROM_ADDRESS" envDefault:"ssh-auth@localhost"`
	ToSuffix    string `env:"MAIL_TO_SUFFIX" envDefault:"@localhost"`
	Subject     string `env:"MAIL_SUBJECT" envDefault:"SSH-Auth"`
}

var options Options

const WELCOME_BODY = "Welcome.\nSending a mail to %s, do you accept? (y/N): "
const MAIL_BODY = `Your authenticatoin token is: %s`
const TOKEN_BODY = "Enter the token you recieved by mail: "

func contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func readN(s io.ReadWriter, l uint, onlyIn []byte) (res []byte, in uint) {
	res = make([]byte, l)
	done := false
	for !done {
		buf := make([]byte, 1)
		_, err := s.Read(buf)
		if err != nil {
			return
		}

		switch buf[0] {
		case 127:
			if in > 0 {
				io.WriteString(s, "\b \b")
				// defaults
				in--
				res[in] = ' '
			}
			break

		case '\r':
			s.Write([]byte("\n\r"))
			done = true
			break

		default:
			if len(onlyIn) > 0 && !contains(onlyIn, buf[0]) {
				break
			}
			if in < l {
				s.Write(buf)
				res[in] = buf[0]
				in += 1
			}
			break
		}
	}
	return
}

func sendmail(dest, token string) (err error) {
	toAddress := dest
	body := fmt.Sprintf(MAIL_BODY, token)

	from := mail.Address{Name: options.FromName, Address: options.FromAddress}
	to := mail.Address{Address: toAddress}

	header := make(map[string]string)
	header["To"] = to.String()
	header["From"] = from.String()
	header["Subject"] = options.Subject
	header["Content-Type"] = `text/html; charset="UTF-8"`
	msg := ""

	for k, v := range header {
		msg += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	c, err := smtp.Dial(options.SMTPServer)
	if err != nil {
		return
	}

	defer c.Close()
	if err = c.Mail(from.String()); err != nil {
		return
	}

	if err = c.Rcpt(to.String()); err != nil {
		return
	}

	w, err := c.Data()
	if err != nil {
		return
	}

	if _, err = w.Write([]byte(msg + "\r\n" + body)); err != nil {
		return
	}

	if err = w.Close(); err != nil {
		return
	}

	err = c.Quit()
	return
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func randomString(n uint) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func main() {
	ssh.Handle(func(s ssh.Session) {
		defer s.Close()
		mail := s.User() + options.ToSuffix
		io.WriteString(s, fmt.Sprintf(WELCOME_BODY, mail))

		buf, read := readN(s, 1, []byte{'y', 'n'})
		if read < 1 || buf[0] != 'y' {
			io.WriteString(s, "Bye!\n")
			return
		}
		token := randomString(options.TokenLength)
		if err := sendmail(mail, token); err != nil {
			log.Printf("Could not send mail: %v", err)
			io.WriteString(s, "Could not send mail\n")
			return
		}
		log.Printf("token for %s is %s", mail, token)
		io.WriteString(s, TOKEN_BODY)
		buf, read = readN(s, options.TokenLength, []byte{})
		if read != options.TokenLength || string(buf) != token {
			io.WriteString(s, "Invalid token.\n")
			return
		}
		io.WriteString(s, "OK\n")
	})

	env.Parse(&options)
	listen := fmt.Sprintf("%s:%d", options.Host, options.Port)
	log.Printf("Listening on %s", listen)
	log.Fatal(ssh.ListenAndServe(listen, nil))
}
