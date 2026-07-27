package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	for {
		addrStr, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		decoded, err := hex.DecodeString(addrStr[:len(addrStr)-1])
		if err != nil {
			fmt.Println(false)
		} else {
			fmt.Println(crypto.IsEdwards25519Point(decoded))
		}
	}
}
