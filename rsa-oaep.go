package main

import (
  "fmt"
  b64 "encoding/base64"
  "crypto/rsa"
  "crypto/rand"
  "golang.org/x/crypto/sha3"
)

// func (pubKey *rsa.PublicKey) print(){
//   Info.Println("Modulus :"+pubKey.N)
//   Info.Println("Public Exponent :"+pubKey.E)
// }
//
// func (privKey *rsa.PrivateKey) print(){
//   Info.Println("Private exponent :"+privKey.D)
//   Info.Println("primes :"+privKey.Primes)
// }


func main(){
  fmt.Println("Generating keys")
  privKey, err := rsa.GenerateKey(rand.Reader, 4096)
  if err!=nil{
    fmt.Println("Error while generating private Key")
  }
  fmt.Println("Getting pub key")
  pubKey := privKey.PublicKey
  // privkey.print()
  // pubkey.print()
  hash := sha3.New512()
  randReader := rand.Reader
  msg := []byte{'d', 'e', 'c', 'r', 'y', 'p', 't', ' ', 'm', 'e'}
  label := []byte{'m','y','_','l', 'a', 'b', 'e', 'l'}
  fmt.Println("OAEP encrypt")
  oeap_out, err := rsa.EncryptOAEP(hash, randReader, &pubKey, msg, label)
  fmt.Println("PKCS encrypt")
  pkcs_out, err := rsa.EncryptPKCS1v15(randReader, &pubKey, msg)
  if(err!=nil){
    fmt.Println("Error while encrypting")
    fmt.Println(err)
  }
  fmt.Println("Done")
  oeap := b64.StdEncoding.EncodeToString(oeap_out)
  pkcs := b64.StdEncoding.EncodeToString(pkcs_out)
  fmt.Println("oeap out : "+oeap)
  fmt.Println("pkcs out : "+pkcs)
  fmt.Println("Doing it again")
  fmt.Println("OAEP encrypt")
  oeap_out, err = rsa.EncryptOAEP(hash, randReader, &pubKey, msg, label)
  fmt.Println("PKCS encrypt")
  pkcs_out, err = rsa.EncryptPKCS1v15(randReader, &pubKey, msg)
  if(err!=nil){
    fmt.Println("Error while encrypting")
    fmt.Println(err)
  }
  fmt.Println("Done")
  oeap = b64.StdEncoding.EncodeToString(oeap_out)
  pkcs = b64.StdEncoding.EncodeToString(pkcs_out)
  fmt.Println("oeap out : "+oeap)
  fmt.Println("pkcs out : "+pkcs)
}
