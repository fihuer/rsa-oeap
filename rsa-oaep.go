package main

import (
  "fmt"
  "time"
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
var start = time.Now()

func encryptOAEP(msg []byte) string{
  fmt.Println("OAEP encrypt")
  oeap_out, _ := rsa.EncryptOAEP(hash, randReader, &pubKey, msg, label)
  oeap := b64.StdEncoding.EncodeToString(oeap_out)
  return oeap
}

func decryptOAEP(msg string) string{
  oeap_in, _ := b64.StdEncoding.DecodeString(msg)
  fmt.Println("OAEP decrypt")
  oeap_out, _ := rsa.DecryptOAEP(hash, randReader, privKey, oeap_in, label)
  return string(oeap_out)
}

func encryptPKCS(msg []byte) string{
  fmt.Println("PKCS encrypt")
  pkcs_out, _ := rsa.EncryptPKCS1v15(randReader, &pubKey, msg)
  pkcs := b64.StdEncoding.EncodeToString(pkcs_out)
  return pkcs
}

func decryptPKCS(msg string) string{
  pkcs_in, _ := b64.StdEncoding.DecodeString(msg)
  fmt.Println("PKCS decrypt")
  pkcs_out, _ := rsa.DecryptPKCS1v15(randReader, privKey, pkcs_in)
  return string(pkcs_out)
}

func main(){
  fmt.Println("Done generation")
  elapsed := time.Since(start)
  fmt.Println("Took : ", elapsed)
  start = time.Now()
  oaep := encryptOAEP(msg)
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
  fmt.Println("oaep out : "+oaep)
  fmt.Println("Decrypting ...")
  start = time.Now()
  fmt.Println("oaep decrypt : "+decryptOAEP(oaep))
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
  start = time.Now()
  pkcs := encryptPKCS(msg)
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
  fmt.Println("pkcs out : "+pkcs)
  start = time.Now()
  fmt.Println("pkcs decrypt : "+decryptPKCS(pkcs))
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
}
