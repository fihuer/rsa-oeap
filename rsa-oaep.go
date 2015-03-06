package main

import (
  "fmt"
  b64 "encoding/base64"
  "crypto/rsa"
  "crypto/rand"
  "golang.org/x/crypto/sha3"
)

var privKey, _ = rsa.GenerateKey(rand.Reader, 4096)
var pubKey = privKey.PublicKey
// privkey.print()
// pubkey.print()
var hash = sha3.New512()
var randReader = rand.Reader
var msg = []byte{'d', 'e', 'c', 'r', 'y', 'p', 't', ' ', 'm', 'e'}
var label = []byte{'m','y','_','l', 'a', 'b', 'e', 'l'}

func encryptOAEP(msg []byte) string{
  fmt.Println("OAEP encrypt")
  oeap_out, _ := rsa.EncryptOAEP(hash, randReader, &pubKey, msg, label)
  oeap := b64.StdEncoding.EncodeToString(oeap_out)
  return oeap
}

func encryptPKCS(msg []byte) string{
  fmt.Println("PKCS encrypt")
  pkcs_out, _ := rsa.EncryptPKCS1v15(randReader, &pubKey, msg)
  pkcs := b64.StdEncoding.EncodeToString(pkcs_out)
  return pkcs
}

func main(){
  fmt.Println("oeap out : "+encryptOAEP(msg))
  fmt.Println("pkcs out : "+encryptPKCS(msg))
}
