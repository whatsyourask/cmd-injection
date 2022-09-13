package main

import "github.com/whatsyourask/cmd-injection-in-input-alert/command_injection"

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

func main() {
	for _, payload := range payloads {
		command_injection.Detect(payload)
	}
}
