package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

func generatePrime(bits int) (*big.Int, error) {
	return rand.Prime(rand.Reader, bits)
}

func run_part_1(ep *big.Int, Np *big.Int) {
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
	e := big.NewInt(65539)
	for new(big.Int).GCD(nil, nil, e, L).Cmp(big.NewInt(1)) != 0 {
		e.Add(e, big.NewInt(2))
	}

	// Calcula o inverso modular d de e em ZL
	d := new(big.Int).ModInverse(e, L)

	// Gera uma chave AES de 128 bits
	s := make([]byte, 16)
	rand.Read(s)

	// Calcula x = s^ep mod Np usando a chave pública do professor
	x := new(big.Int).Exp(new(big.Int).SetBytes(s), ep, Np)

	// Calcula sigx = x^d mod N usando a chave privada do aluno
	sigx := new(big.Int).Exp(x, d, N)

	// Converte valores para hexadecimal
	xHex := hex.EncodeToString(x.Bytes())
	sigxHex := hex.EncodeToString(sigx.Bytes())
	pkaHex := fmt.Sprintf("%x,%x", e, N)

	// Printa (x, sigx, pka)
	fmt.Print("***** Valores para enviar *****\n\n\n")
	fmt.Println("x: ", xHex)
	fmt.Println("sigx: ", sigxHex)
	fmt.Println("pka: ", pkaHex)
	fmt.Print("************ FIM ****************\n\n\n")
	fmt.Println("Valor de s: ", s)

	// Cria e salva o valor de s em um arquivo .txt
	f, _ := os.Create("s.txt")
	defer f.Close()
	f.WriteString(hex.EncodeToString(s))
}
