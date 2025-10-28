package geoip

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	maxmindDownloadURL = "https://download.maxmind.com/app/geoip_download"
	databaseFilename   = "GeoLite2-Country.mmdb"
	dbPath             = "geoip"
)

// DownloadConfig contains MaxMind download configuration
type DownloadConfig struct {
	LicenseKey string
	EditionID  string // "GeoLite2-Country" or similar
	Timeout    time.Duration
}

// DefaultDownloadConfig returns default configuration
func DefaultDownloadConfig(licenseKey string) *DownloadConfig {
	return &DownloadConfig{
		LicenseKey: licenseKey,
		EditionID:  "GeoLite2-Country",
		Timeout:    30 * time.Second,
	}
}

// DownloadDatabase downloads the MaxMind GeoLite2 database
func DownloadDatabase(config *DownloadConfig) error {
	if config.LicenseKey == "" {
		return fmt.Errorf("MaxMind license key is required. Get it from https://www.maxmind.com/en/geolite2/signup")
	}

	// Create geoip directory if it doesn't exist
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return fmt.Errorf("failed to create geoip directory: %w", err)
	}

	dbFilePath := filepath.Join(dbPath, databaseFilename)

	// Check if database already exists and is recent
	if fileExists(dbFilePath) && isFileRecent(dbFilePath, 7*24*time.Hour) {
		fmt.Printf("[INFO] GeoLite2 database already exists and is recent (%s)\n", dbFilePath)
		return nil
	}

	fmt.Printf("[INFO] Downloading MaxMind GeoLite2-Country database...\n")

	// Download the database
	client := &http.Client{
		Timeout: config.Timeout,
	}

	url := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=tar.gz",
		maxmindDownloadURL, config.EditionID, config.LicenseKey)

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// For now, we'll just save the tar.gz and extract it
	// In production, you'd want proper error handling
	tarPath := filepath.Join(dbPath, "geolite2.tar.gz")
	out, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("failed to create tar.gz file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write tar.gz file: %w", err)
	}

	fmt.Printf("[INFO] Downloaded to %s\n", tarPath)

	// Extract tar.gz
	if err := extractTarGz(tarPath, dbPath); err != nil {
		return fmt.Errorf("failed to extract database: %w", err)
	}

	// Find and move the mmdb file to the correct location
	mmdbPath, err := findMMDBFile(dbPath)
	if err != nil {
		return fmt.Errorf("failed to find mmdb file: %w", err)
	}

	if mmdbPath != dbFilePath {
		if err := os.Rename(mmdbPath, dbFilePath); err != nil {
			return fmt.Errorf("failed to move mmdb file: %w", err)
		}
	}

	// Cleanup
	os.Remove(tarPath)
	cleanupExtractedDirs(dbPath)

	fmt.Printf("[INFO] GeoLite2 database downloaded and extracted successfully to %s\n", dbFilePath)
	return nil
}

// fileExists checks if a file exists
func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}

// isFileRecent checks if a file is recent (modified within duration)
func isFileRecent(filepath string, duration time.Duration) bool {
	info, err := os.Stat(filepath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < duration
}

// extractTarGz extracts a tar.gz file
func extractTarGz(tarPath, destPath string) error {
	// Use Go's archive/tar and compress/gzip instead of system commands
	return extractTarGzGo(tarPath, destPath)
}

// extractTarGzGo extracts tar.gz using Go's built-in libraries
func extractTarGzGo(tarPath, destPath string) error {
	file, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destPath, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}

	return nil
}

// findMMDBFile finds the .mmdb file in a directory recursively
func findMMDBFile(searchPath string) (string, error) {
	var found string

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".mmdb" {
			found = path
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if found == "" {
		return "", fmt.Errorf("no .mmdb file found in %s", searchPath)
	}

	return found, nil
}

// cleanupExtractedDirs removes extracted directories
func cleanupExtractedDirs(basePath string) error {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
			// Only remove GeoLite2-* directories
			if entry.Name()[:8] == "GeoLite2" {
				os.RemoveAll(filepath.Join(basePath, entry.Name()))
			}
		}
	}

	return nil
}
