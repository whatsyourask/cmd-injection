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

func findCmdOrOperator(payload string, element_key string) (bool, int) {
	for _, element := range elements[element_key] {
		elementInd := strings.Index(payload, element)
		if elementInd != -1 {
			signature += element_key
			return true, elementInd + len(element)
		}
	}
	return false, -1
}

func findPath(payload string) (bool, int) {
	pathInd := strings.Index(payload, "/")
	if pathInd != -1 {
		signature += "p"
		// fmt.Printf("path at %d\n", pathInd)
		return true, pathInd + 1
	}
	return false, -1
}

func checkSignature() bool {
	for _, alertSignature := range alertSignatures {
		if signature == alertSignature {
			return true
		}
	}
	return false
}

func detectCMDI(payload string) {
	cmdFound, cmdInd := findCmdOrOperator(payload, "c")
	if cmdFound {
		// if command was found then search for path or operator
		findPath(payload[cmdInd:])
		findCmdOrOperator(payload[cmdInd:], "o")
	} else {
		operatorFound, operatorInd := findCmdOrOperator(payload, "o")
		if operatorFound {
			findCmdOrOperator(payload[operatorInd:], "c")
			findPath(payload[operatorInd:])
		}
	}
	alert := checkSignature()
	if alert {
		fmt.Printf("alert for %s payload\n\n", payload)
	}
}

func main() {
	for _, payload := range payloads {
		signature = ""
		detectCMDI(payload)
	}
}
