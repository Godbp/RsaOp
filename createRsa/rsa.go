package createRsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func TestKeyGenerate() {
	// 秘钥长度默认1024
	if err := GenRsaKey(1024); err != nil {
		log.Fatal("密钥文件生成失败！ %v", err)
	}

	log.Println("密钥文件生成成功！ ")
}

func GenRsaKey(bits int) error {

	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)

	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	//dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	err = createFile(publicBlock,  "public.pem")
	err = createFile(priBlock,  "private.pem")
	if err != nil{
		return err
	}
	return nil
}

func createFile(block *pem.Block, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil{
		return err
	}
	return nil
}