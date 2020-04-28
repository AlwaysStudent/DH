package main

import (
	"comment"
	"fmt"
	"log"
	"net"
)

// InitServer is a func that input address by string and output a Listener
// which is listenning the address inputed
func InitServer(Address string) (ServerListener net.Listener) {
	ServerListener, ListenErr := net.Listen("tcp", Address)
	if ListenErr != nil {
		log.Fatal(ListenErr)
	}
	return
}

// HandleUserNeeds is a func to Handle User's Need
func HandleUserNeeds(AcceptConnect net.Conn) {
	SecretKey := comment.ExchangeKey(AcceptConnect)
	PrivateKey, PeerPublicKey := comment.ChangeSign(AcceptConnect, (*SecretKey).Bytes())

	defer AcceptConnect.Close()
	for {
		RecvText, RecvErr := comment.RecvMsg(AcceptConnect, (*SecretKey).Bytes(), PeerPublicKey)
		if RecvErr != nil {
			fmt.Printf("[%s] User Exit...\n", AcceptConnect.RemoteAddr())
			break
		}
		fmt.Printf("[%s](Verified) %s\n", AcceptConnect.RemoteAddr(), RecvText)
		if RecvText == "exit" {
			fmt.Println("User Exit")
			break
		}
		SendErr := comment.SendMsg(AcceptConnect, []byte(RecvText), (*SecretKey).Bytes(), PrivateKey)
		if SendErr != nil {
			fmt.Println(SendErr)
			break
		}
	}
}

func main() {
	Address := "127.0.0.1:8000"
	ServerListener := InitServer(Address)
	defer ServerListener.Close()
	for {
		AcceptConnect, AcceptErr := ServerListener.Accept()
		if AcceptErr != nil {
			log.Fatal(AcceptErr)
		}
		fmt.Printf("[%s] User Login...\n", AcceptConnect.RemoteAddr())
		go HandleUserNeeds(AcceptConnect)
	}
}
