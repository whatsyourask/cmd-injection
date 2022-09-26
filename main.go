package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/whatsyourask/cmd-injection/cmd_injection"
)

func readPayloads(path string) ([]string, int) {
	payloads, err := os.ReadFile(path)
	if err != nil {
		log.Fatalln(err)
	}
	payloadsStr := string(payloads)
	payloadsStrSplit := strings.Split(payloadsStr, "\n")
	payloadsStrSplitLen := len(payloadsStrSplit)
	return payloadsStrSplit, payloadsStrSplitLen
}

func main() {
	payloadsPath := []string{
		"payloads/cmd-injection-seclists.txt",
		"payloads/cmd-injection-custom.txt",
		"payloads/cmd-injection-fp.txt",
	}
	payloads := []string{}
	totalAlertsCount := 0
	for _, path := range payloadsPath {
		tempPayloads, tempPayloadsLen := readPayloads(path)
		payloads = append(payloads, tempPayloads...)
		totalAlertsCount += tempPayloadsLen
	}
	alertCount := 0
	for _, payload := range payloads {
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
	fmt.Println(alertCount)
	fmt.Println(totalAlertsCount)
	if alertCount == totalAlertsCount {
		fmt.Println("ALL TESTS A PASSED")
	}
}
