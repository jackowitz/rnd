package main

import (
	"fmt"
	"io"
	"net"
	"github.com/dedis/crypto/nist"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:7999")
	if err != nil {
		panic("connect: " + err.Error())
	}
	suite := nist.NewAES128SHA256P256()
	buf := make([]byte, suite.SecretLen())
	secret := suite.Secret()
	request := fmt.Sprintf("GENERATE %d RND/1.0\r\n", 5)
	conn.Write([]byte(request))
	for {
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			if err != io.EOF {
				panic("read: " + err.Error())
			}
			break
		}
		if err := secret.Decode(buf); err != nil {
			panic("decode: " + err.Error())
		}
		fmt.Println(secret.String())
	}
}
