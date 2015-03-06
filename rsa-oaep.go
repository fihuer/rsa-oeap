package main

import (
  "fmt"
  "sync"
  "runtime"
  "time"
  "math/big"
  "math"
  b64 "encoding/base64"
  "crypto/rsa"
  "crypto/rand"
  "golang.org/x/crypto/sha3"
)

var privKey, _ = rsa.GenerateKey(rand.Reader, 256)
var pubKey = privKey.PublicKey
// privkey.print()
// pubkey.print()
var hash = sha3.New224()
var randReader = rand.Reader
var msg = []byte{'d', 'e', 'c', 'r', 'y', 'p', 't', ' ', 'm', 'e'}
var label = []byte{'m','y','_','l', 'a', 'b', 'e', 'l'}
var start = time.Now()

type retvals struct{
  res bool
  c big.Int
}

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
  //fmt.Println("PKCS encrypt")
  pkcs_out, _ := rsa.EncryptPKCS1v15(randReader, &pubKey, msg)
  pkcs := b64.StdEncoding.EncodeToString(pkcs_out)
  return pkcs
}

func decryptPKCS(msg string) (string, error){
  pkcs_in, _ := b64.StdEncoding.DecodeString(msg)
  //fmt.Println("PKCS decrypt")
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
  //fmt.Println(c)
  return err==nil
}

func bleichenbacher(c big.Int){
  //res := false
  k := pubKey.N.BitLen()
  B := big.NewInt(0)
  B.Exp(big.NewInt(2), big.NewInt(int64(8*(k-2))), pubKey.N)
  fmt.Println("Searching a PKCS conform message")
  channel := make(chan retvals, 30)
  num_routines:=100
  var wg sync.WaitGroup
  for i:=0; i<num_routines; i++ {
    wg.Add(1)
    go findpkcsconform(c, channel, &wg)
  }
  nb := 0
  c0 := big.NewInt(0)
  for res := range channel {
        //fmt.Println("Conform ? ",res)
        //fmt.Print(len(channel),":")
        nb+=1
        // fmt.Print(nb,":")
        if nb%1000==0{
          fmt.Print("!")
        }
        if res.res {
          fmt.Println("nb of cipher text generated : ",nb)
          fmt.Println("TaDaaaaa")
          fmt.Println("Result : ",res.c)
          c0.Set(&res.c)
          wg.Wait()
          break
        } else{
          wg.Add(1)
          go findpkcsconform(c, channel, &wg)
        }
  }
  i := 1
  min := big.NewInt(0)
  max := big.NewInt(0)
  min = min.Mul(big.NewInt(2), B)
  max = max.Sub(max.Mul(big.NewInt(3), B), big.NewInt(1))
  fmt.Println("Min ", min)
  fmt.Println("Max ", max)
  M := [][][]*big.Int{{{min, max}}}
  fmt.Println("k :",k)
  fmt.Println("B :",B)
  fmt.Println("c0 :",c0)
  fmt.Println("i :",i)
  fmt.Println("M0 :",M[0])
  fmt.Println("Len M0: ", len(M[0]))
  for stopCondition(&M, i ){
    stepTwo(c0, B, i, M)
    break
  }

}

func stepTwo(c0, B *big.Int, i int, M [][][]*big.Int) {
  fmt.Println("Step Two ..")
  s1:= pubKey.N
  div := big.NewInt(3)
  fmt.Println("N : ",pubKey.N)
  fmt.Println("3B mod N: ",div.Mod(div.Mul(div, B),pubKey.N))
  s1 = s1.Mod(s1.Div(pubKey.N, div),pubKey.N)
  fmt.Println("s1 ",s1)
  num_routines:=150
  var wg sync.WaitGroup
  channel := make(chan retvals, 30)
  for i:=0; i<num_routines; i++ {
    wg.Add(1)
    go stepTwoSingle(c0, s1, channel, &wg)
    s1 = s1.Add(s1, big.NewInt(1))
  }
  nb:=0
  for res := range channel {
        //fmt.Println("Conform ? ",res)
        //fmt.Print(len(channel),":")
        nb+=1
        // fmt.Print(nb,":")
        if nb%100000==0{
          fmt.Print("!")
        }
        if nb%10000000==0{
          fmt.Print("###",s1,"###")
        }
        if res.res {
          fmt.Println("nb of cipher text generated : ",nb)
          fmt.Println("TaDaaaaa")
          fmt.Println("Result : ",res.c)
          wg.Wait()
          break
        } else{
          wg.Add(1)
          go stepTwoSingle(c0, s1, channel, &wg)
          s1 = s1.Add(s1, big.NewInt(1))
        }
  }
  M = narrow(s1, B, i, &M)
  fmt.Println("New M : ",M)
  fmt.Println("Len M1", len(M[1]))
}

func narrow(s, B *big.Int, i int, M *[][][]*big.Int)[][][]*big.Int {
  m := *M
  a:=big.NewInt(0)
  b:=big.NewInt(0)
  rmin := big.NewInt(0)
  rmax := big.NewInt(0)
  intervals := make([][]*big.Int,1)
  for j := 0; j < len(m[i-1]); j++ {
        a = m[i-1][j][0]
        b = m[i-1][j][1]
        rmin = rmin.Mul(a, s)
        rmin = rmin.Sub(rmin, big.NewInt(0).Mul(big.NewInt(3),B))
        rmin = rmin.Add(rmin, big.NewInt(1))
        rmin = rmin.Div(rmin, pubKey.N)
        rmax = rmax.Mul(b, s)
        rmax = rmax.Sub(rmax, big.NewInt(0).Mul(big.NewInt(2),B))
        rmax = rmax.Div(rmax, pubKey.N)
        AppendInt(intervals, findInterval(a, b, rmin, rmax, B, s))
        fmt.Println("a :", a)
        fmt.Println("b :", b)
        fmt.Println("rmin :", rmin)
        fmt.Println("rmax :", rmax)
  }
  Append(m, intervals)
  return m
}

func Extend(slice [][][]*big.Int, element [][]*big.Int) [][][]*big.Int {
    n := len(slice)
    if n == cap(slice) {
        // Slice is full; must grow.
        // We double its size and add 1, so if the size is zero we still grow.
        newSlice := make([][][]*big.Int, len(slice), 2*len(slice)+1)
        copy(newSlice, slice)
        slice = newSlice
    }
    slice = slice[0 : n+1]
    slice[n] = element
    return slice
}

func Append(slice [][][]*big.Int, items ...[][]*big.Int) [][][]*big.Int {
    for _, item := range items {
        slice = Extend(slice, item)
    }
    return slice
}

func ExtendInt(slice [][]*big.Int, element []*big.Int) [][]*big.Int {
    n := len(slice)
    if n == cap(slice) {
        // Slice is full; must grow.
        // We double its size and add 1, so if the size is zero we still grow.
        newSlice := make([][]*big.Int, len(slice), 2*len(slice)+1)
        copy(newSlice, slice)
        slice = newSlice
    }
    slice = slice[0 : n+1]
    slice[n] = element
    return slice
}

func AppendInt(slice [][]*big.Int, items ...[]*big.Int) [][]*big.Int {
    for _, item := range items {
        slice = ExtendInt(slice, item)
    }
    return slice
}


func findInterval(a, b, rmin, rmax, B, s *big.Int)[]*big.Int{
  r := rmin
  left := big.NewInt(0)
  right := rmax
  tempLeft := B
  tempRight := B
  for r.Cmp(rmax)==-1{
    tempLeft=B
    tempLeft.Mul(B, big.NewInt(2))
    tempLeft.Add(tempLeft, big.NewInt(0).Mul(r, pubKey.N))
    tempLeft.Div(tempLeft, s)
    tempRight=B
    tempRight.Mul(B, big.NewInt(3))
    tempRight.Sub(tempRight, big.NewInt(1))
    tempRight.Add(tempLeft, big.NewInt(0).Mul(r, pubKey.N))
    tempRight.Div(tempLeft, s)
    if tempLeft.Cmp(left) == 1{
      left = tempLeft
    }
    if tempRight.Cmp(right) == -1{
      right = tempRight
    }
    r.Add(r, big.NewInt(1))
  }
  if a.Cmp(left) == +1{
    left = a
  }
  if b.Cmp(right) == -1{
    right = b
  }
  res := []*big.Int{left, right}
  return res
}

func stepTwoSingle(c0, s *big.Int, channel chan retvals, wg *sync.WaitGroup){
  temp_cipher := c0
  // fmt.Println(s)
  temp_cipher.Mul(s, temp_cipher)
  temp_cipher.Exp(temp_cipher, big.NewInt(int64(pubKey.E)), pubKey.N)
  conform := ispkcsconform(*temp_cipher)
  channel <- retvals{conform, *s}
  wg.Done()
}

func stopCondition(M *[][][]*big.Int, i int) bool{
  m := *M
  //fmt.Println("i ", i)
  //fmt.Println("len M[i-1] ", len(m[i-1]))
  if (i != 1) && (len(m[i-1]) == 1){
    return false
  } else {
    return true
  }
}

func findpkcsconform(c big.Int, channel chan retvals, wg *sync.WaitGroup){
  max := big.NewInt(int64(  math.Pow(2, 30)))
  s, _ := rand.Int(randReader, max)
  temp := big.NewInt(0)
  temp.Mul(&c, s)
  cprim := big.NewInt(0)
  cprim.Exp(temp, big.NewInt(int64(pubKey.E)), pubKey.N)
  res := pkcsconform(*cprim)
  // if res {
  //   fmt.Print("!")
  // } else{
  //   fmt.Print("X")
  // }
  wg.Done()
  channel <- retvals{res, *cprim}
}

func ispkcsconform(c big.Int) bool{
  max := big.NewInt(int64(  math.Pow(2, 30)))
  s, _ := rand.Int(randReader, max)
  temp := big.NewInt(0)
  temp.Mul(&c, s)
  cprim := big.NewInt(0)
  cprim.Exp(temp, big.NewInt(int64(pubKey.E)), pubKey.N)
  res := pkcsconform(*cprim)
  // if res {
  //   fmt.Print("!")
  // } else{
  //   fmt.Print("X")
  // }
  return res
}

func main(){
  fmt.Println("Previous max proces : ",runtime.GOMAXPROCS(9))
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
  dec, err := decryptOAEP(oaep)
  if err != nil{
    fmt.Println(err)
  }
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
