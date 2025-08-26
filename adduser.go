package main

import (
	"fmt"
	"os"

	"github.com/mdp/qrterminal"
	"github.com/pquerna/otp/totp"
)

func AddUser(username string) {

	// generate a TOTP key
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "sneck",
		AccountName: username,
	})

	qrterminal.Generate(key.URL(), qrterminal.L, os.Stderr)

	fmt.Printf("\nusers:\n- %s\n", key.URL())

}
