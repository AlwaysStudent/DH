# 相关封装库函数接口文档

## comment

### comment.go

```go
func ExchangeKey(Connect net.Conn) (SecretKey *big.Int)
```

`ExchangeKey`函数输入一个已经连接的套接字，返回交换并且计算完成的`SecretKey`。
函数内部使用`DH`的工作原理和`RFC3526`标准中约定好的大素数和该素数的原根（在`dh.go`中有体现）

```go
func ChangeSign(Connect net.Conn, Key []byte) (PrivateKey *rsa.PrivateKey, PeerPublicKey *rsa.PublicKey)
```

`ChangeSign`函数输入一个已经连接的套接字和通过`DH`协议交换过的密钥，返回函数中生成的`rsa.PrivateKey`和接收到的对方的`rsa.PublicKey`

```go
func PKCS7Padding(Ciphertext []byte, BlockSize int) (PaddedDta []byte)
```

`PKCS7Padding`函数将明文依照`PKCS7标准`填充到`BlockSize`的整数倍

```go
func PKCS7UnPadding(OrigData []byte) (SourceData []byte)
```

`PKCS7UnPadding`函数将原文进行解填充

```go
func AESCBCEncrypt(RawData, Key []byte) (CipherData []byte, err error)
```

`AESCBCEncrypt`函数使用`Key`对`RawDtata`进行`AES`加密(加密模式为`CBC`)

```go
func AESCBCDecrypt(CipherData, Key []byte) (RawData []byte, err error)
```

`AESCBCDecrypt`函数使用`Key`对`RawDtata`进行`AES`解密(解密模式为`CBC`)

```go
func SendMsg(Connect net.Conn, SendRawText []byte, Key []byte) (err error)
```

`SendMsg`函数负责发送加密后的信息以及信息的`HASHMAC`签名

```go
func RecvMsg(Connect net.Conn, Key []byte) (RawText string, err error)
```

`RecvMsg`函数负责接收信息并解密同时验证其收到的`HASHMAC`签名

## dh

### dh.go

```go
type PublicKey *big.Int
type PrivateKey *big.Int

type Group struct {
    P *big.Int
    G *big.Int
}
```

`DH`的`PublicKey`和`PrivateKey`的类型为`*big.Int`
`Group`（分组）中，`P`代表素数，`G`代表素数的原根

```go
func IsSafePrimeGroup(g *Group, n int) bool
```

`IsSafePrimeGroup`函数判断分组是否是一个安全的素数分组

```go
func IsSafePrimeGroup(g *Group, n int) bool
```

`IsSafePrimeGroup`函数判断分组是否是一个安全的素数分组

```go
func (g *Group) GenerateKey(rand io.Reader) (private PrivateKey, public PublicKey, err error)
```

`GenerateKey`函数使用强随机数生成生成一对密钥

```go
func (g *Group) PublicKey(private PrivateKey) (public PublicKey)
```

`PublicKey`函数返回给定私钥所对应的公钥

```go
func (g *Group) Check(peersPublic PublicKey) (err error)
```

`Check`函数判断对方的公钥是否与自身选用的公钥为同一组

```go
func (g *Group) ComputeSecret(private PrivateKey, peersPublic PublicKey) (secret *big.Int)
```

`ComputeSecret`函数返回经过自己的私钥和对方的公钥联合计算后的密钥

### group.go

```go
func RFC3526_2048() *Group
func RFC3526_3072() *Group
func RFC3526_4096() *Group
```

以上的三个函数分别返回根据`RFC3526`标准定义的分组
`DH`分组详情见 [https://www.ietf.org/rfc/rfc3526.txt](https://www.ietf.org/rfc/rfc3526.txt)
