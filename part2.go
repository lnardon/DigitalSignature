package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

func reverseString(s string) string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

func run_part_2() {
    ciphertextHex := "aqui_colocar_o_ciphertext_em_hexadecimal" // Pode ser uma boa recerber por input do user com o Bubbletea
    sigCHex := "aqui_colocar_a_assinatura_em_hexadecimal" // Pode ser uma boa recerber por input do user com o Bubbletea
    chaveHex := "aqui_colocar_a_chave_aes_em_hexadecimal" // Pode ser uma boa recerber por input do user com o Bubbletea

    ciphertext, _ := hex.DecodeString(ciphertextHex)
    sigC, _ := hex.DecodeString(sigCHex)
    chave, _ := hex.DecodeString(chaveHex)

    iv := ciphertext[:16]
    ciphertext = ciphertext[16:]

    epHex := "2E76A0094D4CEE0AC516CA162973C895"
    NpHex := "aqui_colocar_o_modulo_Np_em_hexadecimal" // Pode ser uma boa recerber por input do user com o Bubbletea
    ep := new(big.Int)
    ep.SetString(epHex, 16)
    Np := new(big.Int)
    Np.SetString(NpHex, 16)
    profPublicKey := &rsa.PublicKey{
        N: Np,
        E: int(ep.Int64()),
    }

    hashedC := sha256.Sum256(ciphertext)
    err := rsa.VerifyPKCS1v15(profPublicKey, crypto.SHA256, hashedC[:], sigC)
    if err != nil {
        fmt.Println("Assinatura inválida:", err)
        os.Exit(1)
    }

    block, err := aes.NewCipher(chave)
    if err != nil {
        fmt.Println("Erro ao criar bloco de cifra AES:", err)
        os.Exit(1)
    }
    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(ciphertext, ciphertext)
    padding := int(ciphertext[len(ciphertext)-1])
    message := string(ciphertext[:len(ciphertext)-padding])

    messageReversed := reverseString(message)

    ivNew := make([]byte, aes.BlockSize)
    rand.Read(ivNew)
    block, err = aes.NewCipher(chave)
    if err != nil {
        fmt.Println("Erro ao criar bloco de cifra AES:", err)
        os.Exit(1)
    }
    mode = cipher.NewCBCEncrypter(block, ivNew)
    paddedMessage := pkcs7Pad([]byte(messageReversed), block.BlockSize())
    ciphertextNew := make([]byte, len(paddedMessage))
    mode.CryptBlocks(ciphertextNew, paddedMessage)

    ciphertextFinal := append(ivNew, ciphertextNew...)

    hashedNew := sha256.Sum256(ciphertextFinal)
	// Pode ser uma boa recerber por input do user com o Bubbletea
    privateKey := &rsa.PrivateKey{
        D: new(big.Int).SetInt64(0), // Colocar o valor de D
        Primes: []*big.Int{
            new(big.Int).SetInt64(0), // Colocar o valor de p
            new(big.Int).SetInt64(0), // Colocar o valor de q
        },
    }
	
    sigNew, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedNew[:]) // Precisa da chave privada
    if err != nil {
        fmt.Println("Erro ao assinar a mensagem:", err)
        os.Exit(1)
    }

    fmt.Printf("Enviar para o professor: Ciphertext = %x, Signature = %x\n", ciphertextFinal, sigNew)
}

func pkcs7Pad(data []byte, blocksize int) []byte {
    padding := blocksize - len(data)%blocksize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padtext...)
}
