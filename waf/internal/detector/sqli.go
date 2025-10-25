package detector

import (
	"regexp"
	"strings"
)

// SQLiDetector detects SQL Injection attacks
type SQLiDetector struct {
	patterns []*regexp.Regexp
}

// NewSQLiDetector creates a new SQL injection detector
func NewSQLiDetector() *SQLiDetector {
	patterns := []string{
		// === BOOLEAN-BASED SQLI (COMPREHENSIVE) ===
		`(?i)\b(or|and)\s*['"]?\s*\d+\s*=\s*\d+['"]?\s*`,           // or 1=1, or "1"="1", or '1'='1'
		`(?i)\b(or|and)\s*['"]1['"]\s*=\s*['"]1['"]\s*`,             // '1'='1', "1"="1"
		`(?i)\b(or|and)\s*['"][^'"]*['"]\s*=\s*['"][^'"]*['"]`,      // 'a'='a' generico
		`(?i)\b(or|and)\s+\d+\s*[<>=]+\s*\d+`,                       // or 1>0, and 2<3
		`(?i)\b(or|and)\s+true`,                                      // or true
		`(?i)\b(or|and)\s+false`,                                     // and false
		`(?i)\b(or|and)\s+null`,                                      // or null

		// === CLASSIC BOOLEAN PATTERNS ===
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
		`(?i)(or\s+'1'\s*=\s*'1)`,
		`(?i)(and\s+'1'\s*=\s*'1)`,
		`(?i)(or\s+"1"\s*=\s*"1)`,
		`(?i)(and\s+"1"\s*=\s*"1)`,

		// === WITH QUOTES/COMMENTS ===
		`(?i)['"]\s*(or|and)\s*['"]1['"]\s*=\s*['"]1['"]`,           // ' OR '1'='1
		`(?i)['"]\s*(or|and)\s*1=1`,                                 // ' OR 1=1
		`(?i)'\s*or\s*'`,                                             // ' or '
		`(?i)"\s*or\s*"`,                                             // " or "
		`(?i)'\s*and\s*'`,                                            // ' and '
		`(?i)"\s*and\s*"`,                                            // " and "

		// === UNION-BASED SQLI ===
		`(?i)(union\s+(all\s+)?select)`,
		`(?i)union\s+select\s+null`,
		`(?i)union\s+select\s+\d+`,
		`(?i)union\s+all\s+select`,
		`(?i)union.*from`,

		// === SQL COMMENTS ===
		`(--|#|/\*|\*/)`,
		`--\s*$`,
		`#\s*`,
		`/\*.*?\*/`,
		`;\s*--`,
		`'\s*--`,
		`"\s*--`,

		// === STACKED QUERIES ===
		`;\s*(drop|delete|update|insert|create|alter|exec|execute|grant|revoke)`,
		`;\s*shutdown`,
		`;\s*xp_cmdshell`,
		`;\s*sp_executesql`,

		// === SQL COMMANDS WITH KEYWORDS ===
		`(?i)\b(select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|table|database|schema)\b`,
		`(?i)\bselect\b.*\bfrom\b`,
		`(?i)\binsert\b.*\binto\b`,
		`(?i)\bupdate\b.*\bset\b`,
		`(?i)\bdelete\b.*\bfrom\b`,
		`(?i)\bdrop\b.*\btable\b`,
		`(?i)\bdrop\b.*\bdatabase\b`,

		// === TIME-BASED BLIND SQLI ===
		`(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()`,
		`(?i)sleep\s*\(\s*\d+\s*\)`,
		`(?i)benchmark\s*\(\s*\d+`,
		`(?i)waitfor\s+delay\s+['"]`,
		`(?i)pg_sleep\s*\(\s*\d+\s*\)`,

		// === STRING MANIPULATION FUNCTIONS ===
		`(?i)(concat\s*\(|char\s*\(|ascii\s*\(|substring\s*\(|substr\s*\(|mid\s*\()`,
		`(?i)concat_ws\s*\(`,
		`(?i)group_concat\s*\(`,
		`(?i)char\(\d+\)`,
		`(?i)chr\(\d+\)`,
		`(?i)unhex\s*\(`,
		`(?i)hex\s*\(`,
		`(?i)conv\s*\(`,

		// === INFORMATION GATHERING ===
		`(?i)information_schema`,
		`(?i)sys\.databases`,
		`(?i)sys\.tables`,
		`(?i)sys\.columns`,
		`(?i)mysql\.user`,
		`(?i)pg_catalog`,
		`(?i)all_tables`,
		`(?i)user_tables`,
		`(?i)\btable_name\b`,
		`(?i)\btable_schema\b`,
		`(?i)\bcolumn_name\b`,
		`(?i)@@version`,
		`(?i)@@datadir`,
		`(?i)version\s*\(`,
		`(?i)database\s*\(`,
		`(?i)user\s*\(`,
		`(?i)current_user`,
		`(?i)session_user`,
		`(?i)system_user`,

		// === CLAUSES ===
		`(?i)(having|group\s+by|order\s+by|limit|offset|into\s+outfile|into\s+dumpfile)`,
		`(?i)having\s+\d+=\d+`,
		`(?i)order\s+by\s+\d+`,
		`(?i)group\s+by\s+\d+`,

		// === COMMENT-BASED EVASION ===
		`'.*?--`,
		`".*?--`,
		`'\s*/\*`,
		`"\s*/\*`,
		`/\*.*?or.*?\*/`,
		`/\*.*?and.*?\*/`,
		`/\*.*?union.*?\*/`,

		// === OBFUSCATION ===
		`\\x[0-9a-f]{2}`, // Hex encoding
		`(?i)0x[0-9a-f]+`, // Hex numbers
		`(?i)char\(0x`, // char(0x...)
		`(?i)%[0-9a-f]{2}`, // URL encoding

		// === ERROR-BASED SQLI ===
		`(?i)extractvalue\s*\(`,
		`(?i)updatexml\s*\(`,
		`(?i)exp\s*\(`,
		`(?i)floor\s*\(.*?rand\s*\(`,
		`(?i)cast\s*\(`,
		`(?i)convert\s*\(`,

		// === BLIND SQLI PATTERNS ===
		`(?i)if\s*\(`,
		`(?i)case\s+when`,
		`(?i)iif\s*\(`,
		`(?i)like\s+['"]%`,
		`(?i)regexp\s+`,
		`(?i)rlike\s+`,

		// === STORED PROCEDURES (DANGEROUS) ===
		`(?i)xp_cmdshell`,
		`(?i)sp_executesql`,
		`(?i)sp_makewebtask`,
		`(?i)sp_oacreate`,
		`(?i)exec\s+master`,
		`(?i)execute\s+immediate`,

		// === DATABASE-SPECIFIC FUNCTIONS ===
		// MySQL
		`(?i)load_file\s*\(`,
		`(?i)into\s+outfile`,
		`(?i)into\s+dumpfile`,
		// PostgreSQL
		`(?i)pg_read_file\s*\(`,
		`(?i)copy\s+.*\bfrom\b`,
		`(?i)copy\s+.*\bto\b`,
		// Oracle
		`(?i)utl_file`,
		`(?i)utl_http`,
		`(?i)dbms_`,
		// MSSQL
		`(?i)openrowset`,
		`(?i)opendatasource`,
		`(?i)openquery`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &SQLiDetector{patterns: compiled}
}

// Detect checks if input contains SQL injection patterns
func (d *SQLiDetector) Detect(input string) (bool, string) {
	// Normalize input
	normalized := strings.ToLower(strings.TrimSpace(input))
	
	// Remove common whitespace variations
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "SQL Injection pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}