package main

import (
	"fmt"
	"strings"
)

var payloads = []string{
	"/usr/bin/cat /etc/passwd",
	"cat /etc/passwd; ls",
	"/usr/bin/cat /etc/passwd & ls",
	"cat /etc/passwd && ls",
	"/usr/bin/cat /etc/passwd | ls",
	"cat /etc/passwd || ls",
	"echo $(cat /etc/passwd)",
	"echo `cat /etc/passwd`",
	"ls||id; ls ||id; ls|| id; ls || id",
	"ls&id; ls &id; ls& id; ls & id",
	"> /tmp/output.txt",
	"< /etc/passwd",
	"https://google.com/search?q=helloworld",
	"foo1=bar1&foo2=bar2",
	"cat/etc/passwd",
	"ls&&whoami",
}

var alertSignatures = []string{
	"cp",
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
	},
	"o": {
		";",
		"|",
		"||",
		"&",
		"&&",
		">",
		"<",
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

func detectCMDI(payload string) {
	splitedPayload := strings.Split(payload, " ")
	signature = ""
	for _, payloadPart := range splitedPayload {
		checkCMDI(payloadPart)
	}
	payloadLength := len(splitedPayload)
	if payloadLength > 1 {
		alert := checkSignature()
		if alert {
			fmt.Printf("alert signature %s for %s payload\n\n", signature, payload)
		}
	} else {
		if len(signature) > 1 && signature != "cp" {
			fmt.Printf("alert signature %s for %s payload\n\n", signature, payload)
		}
	}
}

func main() {
	for _, payload := range payloads {
		detectCMDI(payload)
	}
}
