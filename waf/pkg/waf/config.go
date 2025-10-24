package waf

type Config struct {
	LogPath         string `json:"log_path"`
	RulesPath       string `json:"rules_path"`
	BlockDuration   int    `json:"block_duration_seconds"`
	EnableMetrics   bool   `json:"enable_metrics"`
	MetricsPort     int    `json:"metrics_port"`
	EnableAPI       bool   `json:"enable_api"`
	APIPort         int    `json:"api_port"`
	EnableBlocklist bool   `json:"enable_blocklist"`
}