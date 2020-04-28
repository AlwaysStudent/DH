package main

import (
	"comment"
	"fmt"
	"log"
	"net"
	"os"
)

// InitDial is going to connect server[Address] use tcp
func InitDial(Address string) (DialConnect net.Conn) {
	DialConnect, DialErr := net.Dial("tcp", "127.0.0.1:8000")
	if DialErr != nil {
		log.Fatal(DialErr)
	}
	return
}

func main() {
	Address := "127.0.0.1:8000"
	DialConnect := InitDial(Address)
	SecretKey := comment.ExchangeKey(DialConnect)
	PrivateKey, PeerPublicKey := comment.ChangeSign(DialConnect, (*SecretKey).Bytes())

	defer DialConnect.Close()

	go func() {
		for {
			RecvText, RecvErr := comment.RecvMsg(DialConnect, (*SecretKey).Bytes(), PeerPublicKey)
			if RecvErr != nil {
				fmt.Println(RecvErr)
				break
			}
			fmt.Printf("[%s](Verified) %s\n", DialConnect.RemoteAddr(), RecvText)
			if RecvText == "exit" {
				fmt.Println(RecvErr)
				break
			}
		}
	}()
	for {
		SendBuffer := make([]byte, 1024)
		SendLength, _ := os.Stdin.Read(SendBuffer)
		SendRawText := SendBuffer[:SendLength-2]

		SendErr := comment.SendMsg(DialConnect, SendRawText, (*SecretKey).Bytes(), PrivateKey)
		if string(SendRawText) == "exit" {
			break
		}
		if SendErr != nil {
			fmt.Println(SendErr)
			break
		}
	}

}
