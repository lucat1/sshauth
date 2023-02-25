package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"time"

	"github.com/Khan/genqlient/graphql"
	env "github.com/caarlos0/env/v7"
	"github.com/gliderlabs/ssh"
	"github.com/lucat1/sshauth"
)

type Options struct {
	Host        string `env:"SSH_HOST" envDefault:"0.0.0.0"`
	Port        int    `env:"SSH_PORT" envDefault:"22"`
	TokenLength uint   `env:"TOKEN_LENGTH" envDefault:"6"`

	SMTPServer  string `env:"MAIL_SERVER" envDefault:"localhost:25"`
	FromName    string `env:"MAIL_FROM_NAME" envDefault:"SSH-Auth"`
	FromAddress string `env:"MAIL_FROM_ADDRESS" envDefault:"ssh-auth@localhost"`
	ToSuffix    string `env:"MAIL_TO_SUFFIX" envDefault:"@localhost"`
	Subject     string `env:"MAIL_SUBJECT" envDefault:"Your SSH Auth token"`

	LldapURL      url.URL `env:"LLDAP_URL" envDefault:"http://localhost:17170"`
	LldapUser     string  `env:"LLDAP_USER" envDefault:"admin"`
	LldapPassword string  `env:"LLDAP_PASSWORD" envDefault:"admin"`
}

var (
	options Options
	token   string
	endsAt  = time.Now()
)

const WELCOME_BODY = "Welcome.\nSending a mail to %s, do you accept? (y/N): "
const MAIL_BODY = `Your authenticatoin token is: %s`
const TOKEN_BODY = "Enter the token you recieved by mail: "
const TOKEN_FAILED = "Invalid token. Verification failed.\n"
const TOKEN_RETRY = "Invalid token. Please, try again (you have %d more retries)\n"

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

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func login() (token string, endsAt time.Time, err error) {
	body, err := json.Marshal(LoginForm{
		Username: options.LldapUser,
		Password: options.LldapPassword,
	})
	if err != nil {
		err = fmt.Errorf("Could not serialize login body: %v", err)
		return
	}
	resp, err := http.Post(options.LldapURL.JoinPath("/auth/simple/login").String(), "application/json", bytes.NewReader(body))
	if err != nil {
		err = fmt.Errorf("Error while sending login request: %v", err)
		return
	}
	var res LoginResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		err = fmt.Errorf("Error while decoding login response: %v", err)
		return
	}
	return res.Token, time.Now().Add(time.Hour * time.Duration(24)), nil
}

type Transport struct {
	http.RoundTripper
}

func (ct *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", "Bearer "+token)
	return ct.RoundTripper.RoundTrip(req)
}

func main() {
	var err error
	env.Parse(&options)

	if token, endsAt, err = login(); err != nil {
		log.Fatalf("Could not login into LLDAP: %v", err)
	}

	httpClient := &http.Client{Transport: &Transport{}}
	ctx := context.Background()
	client := graphql.NewClient(options.LldapURL.JoinPath("/graphql").String(), httpClient)

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
		i := 3
		for true {
			io.WriteString(s, TOKEN_BODY)
			buf, read = readN(s, options.TokenLength, []byte{})
			if read != options.TokenLength || string(buf) != token {
				i--
				if i == 0 {
					io.WriteString(s, TOKEN_FAILED)
					return
				} else {
					io.WriteString(s, fmt.Sprintf(TOKEN_RETRY, i))
				}
			} else {
				break
			}
		}
		// check if the user is registered
		res, err := sshauth.CheckUser(ctx, client, s.User())
		if err != nil {
			log.Fatalf("Error while querying graphql: %v", err)
		}
		var uid *string = nil
		for _, user := range res.GetUsers() {
			uid = &user.Id
		}
		if uid != nil {
			// not registered, add new user
		} else {
			// password reset
			io.WriteString(s, "You're already registered\n")
		}
	})

	listen := fmt.Sprintf("%s:%d", options.Host, options.Port)
	log.Printf("Listening on %s", listen)
	log.Fatal(ssh.ListenAndServe(listen, nil))
}
