package detector

import (
	"regexp"
	"strings"
)

// NoSQLInjectionDetector detects NoSQL Injection attacks
type NoSQLInjectionDetector struct {
	patterns []*regexp.Regexp
}

// NewNoSQLInjectionDetector creates a new NoSQL injection detector
func NewNoSQLInjectionDetector() *NoSQLInjectionDetector {
	patterns := []string{
		// === MONGODB OPERATORS ===
		`(?i)\$where`,
		`(?i)\$ne`,
		`(?i)\$gt`,
		`(?i)\$gte`,
		`(?i)\$lt`,
		`(?i)\$lte`,
		`(?i)\$in`,
		`(?i)\$nin`,
		`(?i)\$or`,
		`(?i)\$and`,
		`(?i)\$not`,
		`(?i)\$nor`,
		`(?i)\$exists`,
		`(?i)\$type`,
		`(?i)\$mod`,
		`(?i)\$regex`,
		`(?i)\$text`,
		`(?i)\$search`,
		`(?i)\$all`,
		`(?i)\$elemMatch`,
		`(?i)\$size`,

		// === MONGODB QUERY OPERATORS ===
		`(?i)\$expr`,
		`(?i)\$jsonSchema`,
		`(?i)\$slice`,
		`(?i)\$push`,
		`(?i)\$pull`,
		`(?i)\$pop`,
		`(?i)\$addToSet`,
		`(?i)\$each`,

		// === MONGODB AGGREGATION ===
		`(?i)\$group`,
		`(?i)\$match`,
		`(?i)\$project`,
		`(?i)\$sort`,
		`(?i)\$limit`,
		`(?i)\$skip`,
		`(?i)\$unwind`,
		`(?i)\$lookup`,

		// === MONGODB UPDATES ===
		`(?i)\$set`,
		`(?i)\$unset`,
		`(?i)\$inc`,
		`(?i)\$mul`,
		`(?i)\$rename`,
		`(?i)\$setOnInsert`,
		`(?i)\$min`,
		`(?i)\$max`,
		`(?i)\$currentDate`,

		// === JAVASCRIPT INJECTION IN MONGODB ===
		`(?i)\$where.*function`,
		`(?i)\$where.*\{`,
		`(?i)this\.`,
		`(?i)db\.`,

		// === NOSQL BOOLEAN BYPASS ===
		`(?i)\{"?\$ne"?\s*:\s*null\}`,
		`(?i)\{"?\$ne"?\s*:\s*""\}`,
		`(?i)\{"?\$gt"?\s*:\s*""\}`,
		`(?i)\{"?\$gte"?\s*:\s*""\}`,
		`(?i)\{"?\$regex"?\s*:\s*"\.\*"\}`,
		`(?i)\{"?\$regex"?\s*:\s*"\^"\}`,

		// === AUTHENTICATION BYPASS ===
		`(?i)'\s*\|\|\s*'1'\s*==\s*'1`,
		`(?i)'\s*\|\|\s*true`,
		`(?i)admin'--`,
		`(?i)'\s*\$ne\s*'`,

		// === COUCHDB ===
		`(?i)_all_docs`,
		`(?i)_design/`,
		`(?i)_changes`,
		`(?i)_find`,
		`(?i)_bulk_docs`,

		// === REDIS COMMANDS ===
		`(?i)\bkeys\s+\*`,
		`(?i)\bflushall\b`,
		`(?i)\bflushdb\b`,
		`(?i)\bconfig\s+set`,
		`(?i)\beval\b`,
		`(?i)\bscript\b`,
		`(?i)\bshutdown\b`,

		// === CASSANDRA CQL INJECTION ===
		`(?i)or\s+1\s*=\s*1`,
		`(?i)and\s+1\s*=\s*1`,
		`(?i)allow\s+filtering`,
		`(?i)drop\s+keyspace`,
		`(?i)drop\s+table`,

		// === ELASTICSEARCH ===
		`(?i)_search`,
		`(?i)_bulk`,
		`(?i)_mget`,
		`(?i)script_fields`,
		`(?i)inline.*script`,

		// === NOSQL INJECTION IN JSON ===
		`\{"?\$.*?"?\s*:`,
		`\{.*\$where`,
		`\{.*\$regex`,

		// === MONGODB WHERE CLAUSE INJECTION ===
		`(?i)function\s*\(\s*\)\s*\{`,
		`(?i)return\s+true`,
		`(?i)return\s+this`,

		// === MONGODB MAPREDUCE ===
		`(?i)mapreduce`,
		`(?i)mapReduce`,
		`(?i)\$mapReduce`,

		// === OPERATOR INJECTION IN URL PARAMS ===
		`\[\$ne\]`,
		`\[\$gt\]`,
		`\[\$regex\]`,
		`\[\$where\]`,
		`\[\$in\]`,
		`\[\$nin\]`,

		// === OBJECT INJECTION ===
		`\{.*"\$.*":.*\}`,
		`\{.*'\$.*':.*\}`,

		// === NOSQL TIMING ATTACKS ===
		`(?i)\$where.*sleep`,
		`(?i)function.*sleep`,

		// === WILDCARD INJECTION ===
		`\.\*`,
		`\{\$regex:\s*"\.\*"\}`,

		// === MONGODB COMMAND INJECTION ===
		`(?i)db\..*\.find`,
		`(?i)db\..*\.update`,
		`(?i)db\..*\.remove`,
		`(?i)db\..*\.insert`,
		`(?i)db\..*\.drop`,

		// === NESTED OPERATORS ===
		`\{\s*"\$.*":\s*\{.*"\$`,
		`\$.*\$`,

		// === UNICODE BYPASS ===
		`\\u0024`, // Unicode for $
		`%24`, // URL encoded $

		// === OPERATOR STACKING ===
		`\$ne.*\$regex`,
		`\$gt.*\$lt`,
		`\$or.*\$and`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &NoSQLInjectionDetector{patterns: compiled}
}

// Detect checks if input contains NoSQL injection patterns
func (d *NoSQLInjectionDetector) Detect(input string) (bool, string) {
	// Normalize input
	normalized := strings.ToLower(strings.TrimSpace(input))

	// Check if input contains MongoDB-like syntax
	if strings.Contains(input, "$") || strings.Contains(input, "{") || strings.Contains(normalized, "function") {
		for _, pattern := range d.patterns {
			if pattern.MatchString(input) || pattern.MatchString(normalized) {
				return true, "NoSQL Injection attack detected: " + pattern.String()
			}
		}
	}

	return false, ""
}
