package main

import (
	"fmt"
	"github.com/RsaOp/Rsa"
	"github.com/RsaOp/createRsa"
	"io/ioutil"
)

func main() {
	randomData := []byte("1234567890")
	priKey := GetKeys("D:\\code\\RsaOp\\keyfile\\private.pem")
	pubKey := GetKeys("D:\\code\\RsaOp\\keyfile\\public.pem")
	RsaData, err := Rsa.RsaDecryptByPriKey(randomData, priKey)
	if err != nil{
		fmt.Printf("加密失败 %v\n", err)
		return
	}
	fmt.Printf("加密结果 %s\n", RsaData)
	data, err := Rsa.RsaDecryptByPubKey(pubKey, RsaData)
	if err != nil{
		fmt.Printf("解密失败 %v\n", err)
		return
	}
	fmt.Printf("解密结果 %s\n", data)
	createRsa.TestKeyGenerate()
}

func GetKeys(filePath string) []byte {

	buf, err := ioutil.ReadFile(filePath)
	if err != nil{
		return nil
	}
	return buf
}