package main

import (
	"log"
	"os"

	"github.com/cristalhq/aconfig"
	"github.com/cristalhq/aconfig/aconfigyaml"
)

type Config struct {
	Users      []string `json:"users" usage:"List of user seed URLs, comma-separated"`
	AuthUrl    string   `json:"auth_url" default:"/@authorize" usage:"auth_proxy URL" `
	LoginUrl   string   `json:"login_url" default:"/@login" usage:"Login URL"`
	SuccessUrl string   `json:"success_url" default:"/" usage:"URL to redirect to upon successful login"`
	Timeout    int      `json:"timeout" default:"1440" usage:"Minutes required for a login to time out"`
	Host       string   `json:"host" default:"127.0.0.1" usage:"Host to listen at"`
	Port       int      `json:"port" default:"4302" usage:"Port number to listen at"`
	Allow      []string `json:"allow" usage:"List of explicitly allowed IPs, comma-separated"`
	Deny       []string `json:"deny" usage:"List of explicitly denied IPs, comma-separated"`
}

var cfg Config

func main() {

	if len(os.Args) == 3 && os.Args[1] == "adduser" {
		// Generate new seed url and display it, then exit.
		AddUser(os.Args[2])
		os.Exit(0)
	}

	// Otherwise read config as normal and serve.

	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		AllowUnknownFields: false,
		FileFlag:           "c",
		FlagPrefix:         "cfg",
		FailOnFileNotFound: true,
		Files:              []string{"/etc/nginx/go-sneck.yaml"},
		FileDecoders: map[string]aconfig.FileDecoder{
			".yaml": aconfigyaml.New(),
			".yml":  aconfigyaml.New(),
		},
	})

	err := loader.Load()

	if err != nil {
		log.Fatalf("failed to read configuration file %s", err.Error())
	}

	log.Printf("go-sneck starting")

	ParseLists()
	Serve()

}
