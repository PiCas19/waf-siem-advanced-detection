package detector

import (
	"regexp"
	"strings"
)

// PrototypePollutionDetector detects Prototype Pollution attacks
type PrototypePollutionDetector struct {
	patterns []*regexp.Regexp
}

// NewPrototypePollutionDetector creates a new Prototype Pollution detector
func NewPrototypePollutionDetector() *PrototypePollutionDetector {
	patterns := []string{
		// === BASIC PROTOTYPE POLLUTION ===
		`__proto__`,
		`__PROTO__`,
		`__Proto__`,

		// === CONSTRUCTOR POLLUTION ===
		`constructor\.prototype`,
		`constructor\[["']prototype["']\]`,
		`constructor\["prototype"\]`,
		`constructor\['prototype'\]`,

		// === PROTOTYPE PROPERTY ACCESS ===
		`\.prototype\.`,
		`\["prototype"\]`,
		`\['prototype'\]`,
		`\[["']__proto__["']\]`,

		// === JSON POLLUTION ===
		`\{.*"__proto__".*\}`,
		`\{.*'__proto__'.*\}`,
		`\{.*"constructor".*\}`,
		`\{.*"prototype".*\}`,

		// === URL ENCODED ===
		`__proto__%`,
		`%5F%5Fproto%5F%5F`,
		`%5f%5fproto%5f%5f`,
		`constructor%2Eprototype`,

		// === NESTED PROTOTYPE ACCESS ===
		`__proto__\..*__proto__`,
		`constructor\.prototype\..*constructor`,

		// === ARRAY POLLUTION ===
		`\["__proto__"\]`,
		`\['__proto__'\]`,
		`\[__proto__\]`,

		// === OBJECT.ASSIGN POLLUTION ===
		`Object\.assign.*__proto__`,
		`Object\.create.*__proto__`,

		// === LODASH/UNDERSCORE MERGE ===
		`_.merge.*__proto__`,
		`_.extend.*__proto__`,
		`_.defaults.*__proto__`,

		// === DEEP MERGE POLLUTION ===
		`merge.*__proto__`,
		`extend.*__proto__`,
		`assign.*__proto__`,

		// === QUERY STRING POLLUTION ===
		`\?.*__proto__`,
		`&.*__proto__`,
		`\?.*constructor\.prototype`,
		`&.*constructor\.prototype`,

		// === PROTOTYPE CHAIN MANIPULATION ===
		`__proto__\[`,
		`__proto__\.constructor`,
		`__proto__\.prototype`,

		// === ALTERNATIVE SYNTAX ===
		`\["__proto__"\]\[`,
		`\['__proto__'\]\[`,
		`\.constructor\["prototype"\]`,

		// === PROTOTYPE PROPERTY INJECTION ===
		`__proto__\.isAdmin`,
		`__proto__\.role`,
		`__proto__\.admin`,
		`__proto__\.authenticated`,

		// === NODE.JS SPECIFIC ===
		`__proto__\.toString`,
		`__proto__\.valueOf`,
		`__proto__\.hasOwnProperty`,

		// === BRACKET NOTATION ===
		`\[['"]constructor['"]\]\[['"]prototype['"]\]`,
		`\[["']__proto__["']\]\[`,

		// === POLLUTION VIA SETTERS ===
		`__defineSetter__`,
		`__defineGetter__`,
		`__lookupSetter__`,
		`__lookupGetter__`,

		// === DEEP PROPERTY PATHS ===
		`__proto__\..*\..*`,
		`constructor\.prototype\..*\..*`,

		// === JSON.PARSE POLLUTION ===
		`\{"__proto__":\{`,
		`\{'__proto__':\{`,

		// === PROTOTYPE POLLUTION IN ARRAYS ===
		`\[.*\]\..*__proto__`,
		`\[.*\]\.constructor\.prototype`,

		// === POLLUTED PROPERTIES ===
		`__proto__\.polluted`,
		`constructor\.prototype\.polluted`,

		// === RECURSIVE POLLUTION ===
		`__proto__\..__proto__`,
		`__proto__\.__proto__\.__proto__`,

		// === ENCODED BRACKETS ===
		`%5B__proto__%5D`,
		`%5B"__proto__"%5D`,
		`%5B'__proto__'%5D`,

		// === UNICODE BYPASS ===
		`\\u005f\\u005fproto\\u005f\\u005f`,
		`\u005f\u005fproto\u005f\u005f`,

		// === HEX ENCODING ===
		`\x5f\x5fproto\x5f\x5f`,

		// === POLLUTION IN QUERY PARAMS ===
		`\[__proto__\]\[`,
		`\[constructor\]\[prototype\]`,

		// === SPECIFIC FRAMEWORKS ===
		// Express.js
		`req\.query\.__proto__`,
		`req\.body\.__proto__`,
		`req\.params\.__proto__`,

		// === POLLUTION VIA CLONE ===
		`clone.*__proto__`,
		`deepClone.*__proto__`,

		// === PROTOTYPE POISONING ===
		`Object\.prototype\..*=`,
		`Array\.prototype\..*=`,
		`Function\.prototype\..*=`,

		// === MIDDLEWARE POLLUTION ===
		`middleware.*__proto__`,
		`options\.__proto__`,
		`config\.__proto__`,

		// === POLLUTION IN JSON BODY ===
		`\{"constructor":\{"prototype":`,
		`\{'constructor':\{'prototype':`,

		// === NESTED OBJECT POLLUTION ===
		`\{.*"__proto__":\{.*\}.*\}`,
		`\{.*'__proto__':\{.*\}.*\}`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(`(?i)` + p)
	}

	return &PrototypePollutionDetector{patterns: compiled}
}

// Detect checks if input contains Prototype Pollution patterns
func (d *PrototypePollutionDetector) Detect(input string) (bool, string) {
	// Quick check for common indicators
	inputLower := strings.ToLower(input)
	if !strings.Contains(inputLower, "proto") &&
		!strings.Contains(inputLower, "constructor") &&
		!strings.Contains(inputLower, "prototype") {
		return false, ""
	}

	// Check all patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Prototype Pollution attack detected: " + pattern.String()
		}
	}

	return false, ""
}
