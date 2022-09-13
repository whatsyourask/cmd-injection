package main

import (
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/whatsyourask/cmd-injection-in-input-alert/command_injection"
)

func main() {
	payloads, err := os.ReadFile("command-injection-commix.txt")
	if err != nil {
		log.Fatalln(err)
	}
	payloadsStr := string(payloads)
	payloadsStrSplit := strings.Split(payloadsStr, "\n")
	for _, payload := range payloadsStrSplit {
		decodedPayload, err := url.QueryUnescape(payload)
		if err != nil {
			log.Fatalln(err)
		}
		command_injection.Detect(decodedPayload)
	}
}
