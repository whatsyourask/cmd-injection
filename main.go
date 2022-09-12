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

var signature string = ""

func findCommand(payload string, command string, initInd int) (bool, int) {
	cmdInd := strings.Index(payload, command)
	if cmdInd != -1 {
		signature += "c"
		fmt.Printf("cmd at %d\n", cmdInd)
		return true, cmdInd
	}
	return false, -1
}

func findPath(payload string) bool {
	pathInd := strings.Index(payload, "/")
	if pathInd != -1 {
		signature += "p"
		fmt.Printf("path at %d\n", pathInd)
		return true
	}
	return false
}

func findOperator(payload string, operator string) (bool, int) {
	operatorInd := strings.Index(payload, operator)
	if operatorInd != -1 {
		signature += "o"
		fmt.Printf("operator at %d\n", operatorInd)
		return true, operatorInd
	}
	return false, -1
}

func detectCMDI(payload string) {
	fmt.Printf("payload: %s\n", payload)
	for _, command := range commands {
		cmdFound, cmdInd := findCommand(payload, command, 0)
		if cmdFound {
			cmdLen := len(command)
			payloadPart := payload[cmdInd+cmdLen:]
			fmt.Println(payloadPart)
			pathFound := findPath(payloadPart)
			if pathFound {
				break
			} else {
				for _, operator := range operators {
					operatorFound, operatorInd := findOperator(payloadPart, operator)
					if operatorFound {

					}
				}
			}
			fmt.Printf("signature for payload %s\n\n", signature)
			break
		}
	}
}

func main() {
	// payload := "/usr/bin/cat /etc/passwd"
	// fmt.Println(payload[:])
	// fmt.Println(payload[3:])
	for _, payload := range payloads {
		detectCMDI(payload)
	}
}
