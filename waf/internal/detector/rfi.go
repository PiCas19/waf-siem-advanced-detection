cat > rfi.go << 'EOF'
package detector

import (
	"regexp"
)

type RFIDetector struct {
	patterns []*regexp.Regexp
}

func NewRFIDetector() *RFIDetector {
	patterns := []string{
		`(?i)https?://`,
		`(?i)ftp://`,
		`(?i)%68%74%74%70`,
		`(?i)php://`,
		`(?i)file://`,
		`(?i)data://`,
		`(?i)expect://`,
		`(?i)\\\\`,
		`(?i)smb://`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &RFIDetector{patterns: compiled}
}

func (d *RFIDetector) Detect(input string) (bool, string) {
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Remote File Inclusion pattern detected"
		}
	}
	
	return false, ""
}