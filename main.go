package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/whatsyourask/cmd-injection/cmd_injection"
)

func main() {
	payloads, err := os.ReadFile("command-injection-commix.txt")
	if err != nil {
		log.Fatalln(err)
	}
	payloadsStr := string(payloads)
	payloadsStrSplit := strings.Split(payloadsStr, "\n")
	payloadsStrSplitLen := len(payloadsStrSplit)
	payloadsStrSplit = payloadsStrSplit[:payloadsStrSplitLen-1]
	alertCount := 0
	for _, payload := range payloadsStrSplit {
		decodedPayload, err := url.QueryUnescape(payload)
		// fmt.Printf("PAYLOAD: %s\n", decodedPayload)
		if err != nil {
			log.Fatalln(err)
		}
		alert := cmd_injection.Detect(decodedPayload)
		if alert {
			alertCount++
		} else {
			// fmt.Printf("NOT PASSED %s\n\n", decodedPayload)
		}
	}
	// fmt.Println(alertCount)
	// fmt.Println(payloadsStrSplitLen - 1)
	if alertCount == payloadsStrSplitLen-1 {
		fmt.Println("ALL TESTS A PASSED")
	}
}
