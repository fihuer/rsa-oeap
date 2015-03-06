package main

import (
  "fmt"
  "time"
  "math/big"
  "math"
  b64 "encoding/base64"
  "crypto/rsa"
  "crypto/rand"
  "golang.org/x/crypto/sha3"
)

var privKey, _ = rsa.GenerateKey(rand.Reader, 4096)
var pubKey = privKey.PublicKey
// privkey.print()
// pubkey.print()
var hash = sha3.New224()
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

func decryptOAEP(msg string) (string, error){
  oeap_in, _ := b64.StdEncoding.DecodeString(msg)
  fmt.Println("OAEP decrypt")
  oeap_out, err := rsa.DecryptOAEP(hash, randReader, privKey, oeap_in, label)
  return string(oeap_out), err
}

func encryptPKCS(msg []byte) string{
  fmt.Println("PKCS encrypt")
  pkcs_out, _ := rsa.EncryptPKCS1v15(randReader, &pubKey, msg)
  pkcs := b64.StdEncoding.EncodeToString(pkcs_out)
  return pkcs
}

func decryptPKCS(msg string) (string, error){
  pkcs_in, _ := b64.StdEncoding.DecodeString(msg)
  fmt.Println("PKCS decrypt")
  pkcs_out, err := rsa.DecryptPKCS1v15(randReader, privKey, pkcs_in)
  return string(pkcs_out), err
}

func toInt(msg string) big.Int{
  b_msg, _ := b64.StdEncoding.DecodeString(msg)
  val := new(big.Int)
  val.SetBytes(b_msg)
  return *val
}

func fromInt(int_msg big.Int) string{
  b := int_msg.Bytes()
  val := b64.StdEncoding.EncodeToString(b)
  return val
}

func pkcsconform(c big.Int) bool{
  b := fromInt(c)
  _, err := decryptPKCS(b)
  fmt.Println(c)
  return err==nil
}

func bleichenbacher(c big.Int){
  cprim := big.NewInt(0)
  old := big.NewInt(0)
  fmt.Println("Searching a PKCS conform message")
  for !pkcsconform(*cprim){
    fmt.Println("Same as previous : ", cprim==old)
    max := big.NewInt(int64(  math.Pow(2, 30)))
    s, _ := rand.Int(randReader, max)
    temp := big.NewInt(0)
    temp.Mul(&c, s)
    cprim = big.NewInt(0)
    cprim.Exp(temp, big.NewInt(int64(pubKey.E)), pubKey.N)
    fmt.Println(pkcsconform(*cprim))
  }

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
  dec, _ := decryptOAEP(oaep)
  fmt.Println("oaep decrypt : "+dec)
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
  start = time.Now()
  pkcs := encryptPKCS(msg)
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
  fmt.Println("pkcs out : "+pkcs)
  start = time.Now()
  dec, _ = decryptPKCS(pkcs)
  fmt.Println("pkcs decrypt : "+dec)
  elapsed = time.Since(start)
  fmt.Println("Took : ", elapsed)
  c := toInt(pkcs)
  bleichenbacher(c)
}
