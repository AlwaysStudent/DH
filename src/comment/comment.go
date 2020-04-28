package comment

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"dh"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
)

// ExchangeKey is going to negotiate secret keys with each other
func ExchangeKey(Connect net.Conn) (SecretKey *big.Int) {
	Group := dh.RFC3526_2048()
	PrivateKey, PublicKey, GenerateKeyErr := Group.GenerateKey(nil)
	if GenerateKeyErr != nil {
		log.Fatal(GenerateKeyErr)
	}
	// fmt.Println((*PrivateKey).String())
	// fmt.Println((*PublicKey).String())

	RecvBuffer := make([]byte, 4096)
	Connect.Write((*PublicKey).Bytes())
	RecvLength, RecvErr := Connect.Read(RecvBuffer)
	if RecvErr != nil {
		log.Fatal(RecvErr)
	}
	PeerPublicKey := new(big.Int).SetBytes(RecvBuffer[:RecvLength])
	// fmt.Println(PeerPublicKey)
	if CheckErr := Group.Check(PeerPublicKey); CheckErr != nil {
		log.Fatal(CheckErr)
	}
	SecretKey = Group.ComputeSecret(PrivateKey, PeerPublicKey)
	return
}

// ChangeSign is going to Change RSA PublicKey to verify the msg
func ChangeSign(Connect net.Conn, Key []byte) (PrivateKey *rsa.PrivateKey, PeerPublicKey *rsa.PublicKey) {
	PrivateKey, GenerateKeyErr := rsa.GenerateKey(rand.Reader, 1024)
	if GenerateKeyErr != nil {
		log.Fatal(GenerateKeyErr)
	}
	if err := PrivateKey.Validate(); err != nil {
		log.Fatal(err)
	}
	N := (*PrivateKey.PublicKey.N).Bytes()
	E := []byte(strconv.Itoa((PrivateKey.PublicKey.E)))
	NBuf, EBuf := make([]byte, 2048), make([]byte, 2048)
	PeerPublicKey = new(rsa.PublicKey)

	CipherN, _ := AESCBCEncrypt(N, Key[:aes.BlockSize])
	Connect.Write(CipherN)
	NLen, NErr := Connect.Read(NBuf)
	if NErr != nil {
		log.Fatal(NErr)
	}
	DecryptedN, _ := AESCBCDecrypt(NBuf[:NLen], Key[:aes.BlockSize])
	PeerPublicKey.N = new(big.Int).SetBytes(DecryptedN)

	CipherE, _ := AESCBCEncrypt(E, Key[:aes.BlockSize])
	Connect.Write(CipherE)
	ELen, EErr := Connect.Read(EBuf)
	if EErr != nil {
		log.Fatal(nil)
	}
	DecryptedE, _ := AESCBCDecrypt(EBuf[:ELen], Key[:aes.BlockSize])
	PeerPublicKey.E, _ = strconv.Atoi(string(DecryptedE))
	return
}

// PKCS7Padding use PKCS7 to fill the length of Ciphertext to integer times of BlockSize
func PKCS7Padding(Ciphertext []byte, BlockSize int) (PaddedDta []byte) {
	Padding := BlockSize - len(Ciphertext)%BlockSize
	Padtext := bytes.Repeat([]byte{byte(Padding)}, Padding)
	PaddedDta = append(Ciphertext, Padtext...)
	return
}

// PKCS7UnPadding is going to handle Padded text to normal data
func PKCS7UnPadding(OrigData []byte) (SourceData []byte) {
	Length := len(OrigData)
	UnPadding := int(OrigData[Length-1])
	SourceData = OrigData[:(Length - UnPadding)]
	return
}

// AESCBCEncrypt makes RawData to CipherData by using key
func AESCBCEncrypt(RawData, Key []byte) (CipherData []byte, err error) {
	BlockSize := aes.BlockSize
	AESBlock, NewCipherErr := aes.NewCipher(Key)
	if NewCipherErr != nil {
		log.Fatal(NewCipherErr)
	}

	RawData = PKCS7Padding(RawData, BlockSize)
	CipherData = make([]byte, BlockSize+len(RawData))
	InitVecter := CipherData[:BlockSize]
	if _, ReadErr := io.ReadFull(rand.Reader, InitVecter); ReadErr != nil {
		log.Fatal(ReadErr)
	}

	Mode := cipher.NewCBCEncrypter(AESBlock, InitVecter)
	Mode.CryptBlocks(CipherData[BlockSize:], RawData)

	err = nil
	return
}

// AESCBCDecrypt makes CipherData to RawData by using key
func AESCBCDecrypt(CipherData, Key []byte) (RawData []byte, err error) {
	BlockSize := aes.BlockSize
	AESBlock, NewCipherErr := aes.NewCipher(Key)
	if NewCipherErr != nil {
		log.Fatal(NewCipherErr)
	}
	if len(CipherData) < BlockSize {
		err = errors.New("CipherText is too short")
		RawData = []byte("")
		return
	}
	InitVecter := CipherData[:BlockSize]
	CipherData = CipherData[BlockSize:]

	if len(CipherData)%BlockSize != 0 {
		err = errors.New("CipherText is not interger times of the blocksize")
		RawData = []byte("")
		return
	}
	Mode := cipher.NewCBCDecrypter(AESBlock, InitVecter)
	Mode.CryptBlocks(CipherData, CipherData)
	RawData = PKCS7UnPadding(CipherData)
	err = nil
	return
}

// SendMsg is going to use Connect to send message encrypted by key
func SendMsg(Connect net.Conn, SendRawText []byte, Key []byte, PrivateKey *rsa.PrivateKey) (err error) {
	SendCipherText, EncryptErr := AESCBCEncrypt(SendRawText, Key[:aes.BlockSize])
	if EncryptErr != nil {
		err = EncryptErr
		return
	}
	Connect.Write(SendCipherText)
	Hash := sha256.New()
	Hash.Write(SendRawText)
	Sign, SignErr := rsa.SignPKCS1v15(rand.Reader, PrivateKey, crypto.SHA256, Hash.Sum(nil))
	if SignErr != nil {
		err = SignErr
		return
	}
	Connect.Write(Sign)
	return nil
}

// RecvMsg is going to use Connect to recv message decrypted by key
func RecvMsg(Connect net.Conn, Key []byte, PeerPublicKey *rsa.PublicKey) (RawText string, err error) {
	RecvBuffer := make([]byte, 1024)
	SignBuffer := make([]byte, 2048)
	RecvLength, RecvErr := Connect.Read(RecvBuffer)
	RawText = ""
	if RecvErr != nil {
		err = RecvErr
		return
	}
	RecvCipherText := RecvBuffer[:RecvLength]
	RecvRawText, DecryptErr := AESCBCDecrypt(RecvCipherText, Key[:aes.BlockSize])
	if DecryptErr != nil {
		err = DecryptErr
		return
	}

	SignLength, RecvSignErr := Connect.Read(SignBuffer)
	if RecvSignErr != nil {
		err = RecvSignErr
		return
	}
	Sign := SignBuffer[:SignLength]
	Hash := sha256.New()
	Hash.Write(RecvRawText)
	VerifyErr := rsa.VerifyPKCS1v15(PeerPublicKey, crypto.SHA256, Hash.Sum(nil), Sign)
	if VerifyErr != nil {
		err = VerifyErr
		return
	}

	RawText = string(RecvRawText[:len(RecvRawText)])
	err = nil
	return
}
