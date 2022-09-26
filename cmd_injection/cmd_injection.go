package cmd_injection

import (
	"log"
	"strings"
)

var alertSignatures = []string{
	"cp",
	"co",
	"cop",
	"cpo",
	"op",
	"oc",
}

var elements = map[string][]string{
	"c": {
		"cat",
		"echo",
		"whoami",
		"ping",
		"traceroute",
		"bash",
		"sh",
		"ls",
		"nc",
		"ncat",
		"python3",
		"python",
		"socat",
		"rm",
	},
	"o": {
		";",
		"|",
		"||",
		"&",
		"&&",
		">",
		"<",
		"$(",
	},
}

var signature string

func findCmdOrOperator(payloadPart string, element_key string) {
	for _, element := range elements[element_key] {
		elementInd := strings.Index(payloadPart, element)
		if elementInd != -1 {
			signature += element_key
		}
	}
}

func findPath(payloadPart string) {
	pathInd := strings.Index(payloadPart, "/")
	if pathInd != -1 {
		signature += "p"
		// fmt.Printf("path at %d\n", pathInd)
	}
}

func checkSignature() bool {
	for _, alertSignature := range alertSignatures {
		if strings.Contains(signature, alertSignature) {
			return true
		}
	}
	return false
}

func checkCMDI(payloadPart string) {
	findCmdOrOperator(payloadPart, "c")
	findPath(payloadPart)
	findCmdOrOperator(payloadPart, "o")
}

func Detect(payload string) bool {
	splitedPayload := strings.Split(payload, " ")
	signature = ""
	for _, payloadPart := range splitedPayload {
		checkCMDI(payloadPart)
	}
	payloadLength := len(splitedPayload)
	log.Printf("Signature %s was created for %s payload\n\n", signature, payload)
	alert := false
	if payloadLength > 1 {
		alert = checkSignature()

	}
	log.Printf("Signature %s with alert %d for %s payload\n\n", signature, alert, payload)
	return alert
}
