package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/mail"
	"net/smtp"
	"net/url"
	"regexp"
	"time"

	env "github.com/caarlos0/env/v7"
	"github.com/gliderlabs/ssh"
	ldap "github.com/go-ldap/ldap/v3"
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

	LdapURI          string  `env:"LDAP_URI" envDefault:"ldap://localhost:3890"`
	LldapURI         url.URL `env:"LLDAP_URI" envDefault:"https://localhost:17170"`
	LdapBindDN       string  `env:"LDAP_BIND_DN" envDefault:"uid=admin,ou=people,dc=example,dc=com"`
	LdapBindPassword string  `env:"LDAP_BIND_PASSWORD" envDefault:"admin"`
	LdapUserScope    string  `env:"LDAP_USER_SCOPE" envDefault:"ou=people,dc=example,dc=com"`

	PasswordMin    uint   `env:"PASSWORD_MIN" envDefault:"8"`
	PasswordMax    uint   `env:"PASSWORD_MAX" envDefault:"32"`
	PasswordRegexp string `env:"PASSWORD_REGEXP" envDefault:"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"`
}

var (
	options        Options
	token          string
	endsAt         = time.Now()
	passwordRegexp *regexp.Regexp
)

const WELCOME_BODY = "Welcome.\nSending a mail to %s, do you accept? (y/N): "
const MAIL_BODY = `Your authenticatoin token is: %s`
const TOKEN_BODY = "Enter the token you recieved by mail: "
const TOKEN_FAILED = "Invalid token. Verification failed.\n"
const TOKEN_RETRY = "Invalid token. Please, try again (you have %d more retries)\n"
const ALREADY_REGISTERED = "You're already registered.\nYou can authenticate over at\n\t%s\nto manage your account. Bye!"
const PASWORD_RULES = "Please, enter your password twice. It must respect the following rules:\n- The length must be between %d and %d (included)\n- It must contain at least one letter and one digit\n"
const PASSWORD_FAILED = "Password attempts failed. Logging out."
const REGISTRATION_SUCCESS = "You are now registered! You can authenticate over at\n\t%s\nto manage your account. Bye!"

func contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func readN(s io.ReadWriter, l uint, onlyIn []byte, write bool) (res []byte, in uint) {
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
				if write {
					io.WriteString(s, "\b \b")
				}
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
				if write {
					s.Write(buf)
				}
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

var (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	runes   = []rune(letters)
)

func randomString(n uint) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = runes[rand.Intn(len(runes))]
	}
	return string(b)
}

func readPassword(s io.ReadWriter) (ok bool, ans string) {
	passwd, read := readN(s, options.PasswordMax, []byte(letters), false)
	if read < options.PasswordMin {
		return false, "Password is too short"
	}
	if !passwordRegexp.Match([]byte(passwd)) {
		return false, "Password does not comply with the rules"
	}
	return true, string(passwd)
}

func bind() (*ldap.Conn, error) {
	l, err := ldap.DialURL(options.LdapURI)
	if err != nil {
		return nil, fmt.Errorf("Could not connect to the LDAP server: %v", err)
	}

	if err := l.Bind(options.LdapBindDN, options.LdapBindPassword); err != nil {
		return nil, fmt.Errorf("Could not bind with the given user: %v", err)
	}
	return l, nil
}

func exists(l *ldap.Conn, uid string) (bool, error) {
	searchRequest := ldap.NewSearchRequest(
		options.LdapUserScope,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(uid=%s))", ldap.EscapeFilter(uid)),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false, err
	}
	return len(sr.Entries) > 0, nil
}

func register(l *ldap.Conn, uid, email, password string) error {
	user := fmt.Sprintf("uid=%s,", uid) + options.LdapUserScope
	addRequest := ldap.AddRequest{
		DN: user,
		Attributes: []ldap.Attribute{
			ldap.Attribute{"email", []string{email}},
		},
	}

	if err := l.Add(&addRequest); err != nil {
		return fmt.Errorf("Could not add new user: %v", err)
	}

	passwordModifyRequest := ldap.PasswordModifyRequest{
		UserIdentity: user,
		NewPassword:  password,
	}
	if _, err := l.PasswordModify(&passwordModifyRequest); err != nil {
		return fmt.Errorf("Could not add a password to the new user: %v", err)
	}
	return nil
}

func main() {
	env.Parse(&options)
	passwordRegexp = regexp.MustCompile(options.PasswordRegexp)

	ssh.Handle(func(s ssh.Session) {
		defer s.Close()
		user := s.User()
		mail := user + options.ToSuffix
		io.WriteString(s, fmt.Sprintf(WELCOME_BODY, mail))

		buf, read := readN(s, 1, []byte{'y', 'n'}, true)
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
			buf, read = readN(s, options.TokenLength, []byte{}, true)
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
		// initalize the ldap connection
		l, err := bind()
		if err != nil {
			log.Fatalf("Could not bind to LDAP: %v", err)
		}
		defer l.Close()
		exists, err := exists(l, user)
		if err != nil {
			log.Fatalf("Error while searching LDAP user: %v", err)
		}
		if exists {
			// already registered
			io.WriteString(s, fmt.Sprintf(ALREADY_REGISTERED, options.LldapURI.JoinPath("/login").String()))
			return
		}

		// not registered, add new user
		io.WriteString(s, "You're not registered. Proceeding with the registration process\n")
		io.WriteString(s, fmt.Sprintf(PASWORD_RULES, options.PasswordMin, options.PasswordMax))
		passwd, i := "", 3
		for true {
			io.WriteString(s, "Password: ")
			ok, firstPasswd := readPassword(s)
			i--
			if !ok {
				io.WriteString(s, firstPasswd+"\n")
				if i <= 0 {
					io.WriteString(s, PASSWORD_FAILED)
					return
				}
			} else {
				passwd = firstPasswd
				break
			}
		}
		for true {
			io.WriteString(s, "Repeat your password: ")
			ok, secondPassword := readPassword(s)
			i--
			if ok && secondPassword != passwd {
				ok = false
				secondPassword = "Passwords don't match"
			}
			if !ok {
				io.WriteString(s, secondPassword+"\n")
				if i <= 0 {
					io.WriteString(s, PASSWORD_FAILED)
					return
				}
			} else {
				break
			}
		}
		io.WriteString(s, "Registering user with the given password\n")
		if err := register(l, user, mail, passwd); err != nil {
			log.Fatalf("Error while registering a new user with LDAP: %v", err)
		}
		io.WriteString(s, fmt.Sprintf(ALREADY_REGISTERED, options.LldapURI.JoinPath("/login").String()))
	})

	listen := fmt.Sprintf("%s:%d", options.Host, options.Port)
	log.Printf("Listening on %s", listen)
	log.Fatal(ssh.ListenAndServe(listen, nil))
}
