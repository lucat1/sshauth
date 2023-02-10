package main

import (
	"bufio"
	"fmt"
	"io"
	"log"

	env "github.com/caarlos0/env/v7"
	"github.com/gliderlabs/ssh"
)

type Options struct {
	Host string `env:"SSH_HOST" envDefault:"0.0.0.0"`
	Port int    `env:"SSH_PORT" envDefault:"22"`
}

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

func main() {
	ssh.Handle(func(s ssh.Session) {
		defer s.Close()
		io.WriteString(s, "enter: ")

		buf, read := readN(s, 1, []byte{'y', 'n'})
		if read < 1 || buf[0] != 'y' {
			io.WriteString(s, "Bye!\n")
			return
		}
		reader := bufio.NewReader(s)
		str, _ := reader.ReadString('\r')
		fmt.Printf("ans %s\n", str)
		io.WriteString(s, str+"\n")
	})

	options := Options{}
	env.Parse(&options)
	listen := fmt.Sprintf("%s:%d", options.Host, options.Port)
	log.Printf("Listening on %s", listen)
	log.Fatal(ssh.ListenAndServe(listen, nil))
}
