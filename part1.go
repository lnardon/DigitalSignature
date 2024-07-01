package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

func generatePrime(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

func run_part_1() {
	// Info cedida no PDF
	epHex := "2E76A0094D4CEE0AC516CA162973C895"
	NpHex := "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCFDE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A59490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BBF530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391"

	ep := new(big.Int)
	ep.SetString(epHex, 16)

	Np := new(big.Int)
	Np.SetString(NpHex, 16)

	// profPublicKey := &rsa.PublicKey{
	// 	N: Np,
	// 	E: int(ep.Int64()),
	// }

	// Gerar dois números primos p e q
	p, _ := generatePrime(1024)
	q, _ := generatePrime(1024)

	// N = p*q
	N := new(big.Int).Mul(p, q)

	// L = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	L := new(big.Int).Mul(pMinus1, qMinus1)

	// MDC(e, L) = 1
	e := big.NewInt(65537)
	for new(big.Int).GCD(nil, nil, e, L).Cmp(big.NewInt(1)) != 0 {
		e.Add(e, big.NewInt(2))
	}

	// Calcular o inverso modular d de e em ZL
	d := new(big.Int).ModInverse(e, L)

	// Gerar uma chave AES de 128 bits
	s := make([]byte, 16)
	rand.Read(s)

	// Calcular x = s^ep mod Np usando a chave pública do professor
	x := new(big.Int).Exp(new(big.Int).SetBytes(s), ep, Np)

	// Calcular sigx = x^d mod N usando a chave privada do aluno
	sigx := new(big.Int).Exp(x, d, N)

	// Converter valores para hexadecimal para envio
	xHex := hex.EncodeToString(x.Bytes())
	sigxHex := hex.EncodeToString(sigx.Bytes())
	pkaHex := fmt.Sprintf("%x,%x", e, N)

	// Valores (x, sigx, pka)
	fmt.Print("***** Valores para enviar *****\n\n\n")
	fmt.Println("x: ", xHex)
	fmt.Println("sigx: ", sigxHex)
	fmt.Println("pka: ", pkaHex)
	fmt.Print("************ FIM ****************\n\n\n")
}
