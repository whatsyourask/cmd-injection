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

var commands = []string{
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
}

var operators = []string{
	";",
	"|",
	"||",
	"&",
	"&&",
	">",
	"<",
}

var alertSignatures = []string{
	"cp",
	"cop",
	"cpo",
	"op",
	"oc",
}

var signature string

func findCMD(payload string) (bool, int) {
	for _, command := range commands {
		cmdInd := strings.Index(payload, command)
		if cmdInd != -1 {
			signature += "c"
			// fmt.Printf("cmd at %d\n", cmdInd)
			return true, cmdInd + len(command)
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

func findOperator(payload string) (bool, int) {
	for _, operator := range operators {
		operatorInd := strings.Index(payload, operator)
		if operatorInd != -1 {
			signature += "o"
			// fmt.Printf("operator at %d\n", operatorInd)
			return true, operatorInd + len(operator)
		}
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
	cmdFound, cmdInd := findCMD(payload)
	if cmdFound {
		// if command was found then search for path or operator
		findPath(payload[cmdInd:])
		findOperator(payload[cmdInd:])
	} else {
		operatorFound, operatorInd := findOperator(payload)
		if operatorFound {
			findCMD(payload[operatorInd:])
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
