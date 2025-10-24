package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/PiCas19/waf-siem-advanced-detection/waf/pkg/waf"
)

func main() {
	caddycmd.Main()
}