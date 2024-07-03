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
    ciphertextHex := "CD49E969D6531CCA50DC37787AA5687A1CBB56DB0941946F3ED0E9C298BC463584C416F24149767610685C034B417125D7796856BF2C1928ECDC71D2412B0876FBC043AD79780535FEB73969E6907799" // Pode ser uma boa recerber por input do user com o Bubbletea
    sigCHex := "1944DB73B7AE2E780B20B3B0EE49E17E465F37502729440C11D8001BDC6CB74F934BED3182CEC10F4093CE29BA0B3D55E86A3849584A83A8A5008BEBE7EC2771B51CE911CF679F0EE1CA2DAE3CC7E736FFD6553CB4E2936EE6673992F31095756ED0C1AE9F324B81D9D674A1EBA2B3E189D767D7C55645BA41F4066F2B4B938095E36501060E6DA07EC97DD051908546156B05806BF51F958084C17B54F44D7BED706CCCCD77303760EBBF5105BC8DF21F1280386A45B76B741A181F35929D1482E78258BB88C3FF3C1C23E701D0D3EB069EBB537D264602D065DB78E4A70EADCA0E06262235EBE040AE75467F08E4F9C3F9CC2DDF08727C60BDB359ADDD5C2B" // Pode ser uma boa recerber por input do user com o Bubbletea
    chaveHex := "74F520A043E7AEF1A9F0942C0A4A7DC1"

    ciphertext, _ := hex.DecodeString(ciphertextHex)
    sigC, _ := hex.DecodeString(sigCHex)
    chave, _ := hex.DecodeString(chaveHex)

    iv := ciphertext[:16]
    ciphertext = ciphertext[16:]

    epHex := "2E76A0094D4CEE0AC516CA162973C895"
    NpHex := "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCFDE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A59490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BBF530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391" // Pode ser uma boa recerber por input do user com o Bubbletea
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
        D: new(big.Int).SetInt64(0),
        Primes: []*big.Int{
            new(big.Int).SetInt64(0), // valor de p
            new(big.Int).SetInt64(0), // valor de q
        },
    }
	
    sigNew, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedNew[:])
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
