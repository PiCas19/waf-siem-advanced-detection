module github.com/PiCas19/waf-siem-advanced-detection/waf

go 1.22

require (
	github.com/caddyserver/caddy/v2 v2.7.6
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/sqlite v1.5.4
	gorm.io/gorm v1.25.5
)

// Local path for development
replace github.com/PiCas19/waf-siem-advanced-detection/waf => ./
