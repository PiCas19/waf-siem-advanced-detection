package rules

type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity" json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Patterns    []string `yaml:"patterns" json:"patterns"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Actions     []string `yaml:"actions" json:"actions"` // block, log, alert
}