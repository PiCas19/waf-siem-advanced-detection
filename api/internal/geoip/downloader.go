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

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

const (
	maxmindDownloadURL = "https://download.maxmind.com/app/geoip_download"
	databaseFilename   = "GeoLite2-Country.mmdb"
	dbPath             = "geoip"
)

// HTTPClient interface per dependency injection
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// FileSystem interface per operazioni su file system
type FileSystem interface {
	MkdirAll(path string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	Open(name string) (*os.File, error)
	Create(name string) (*os.File, error)
	Remove(name string) error
	Rename(oldpath, newpath string) error
	ReadDir(dirname string) ([]os.DirEntry, error)
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
}

// RealFileSystem implementa FileSystem usando il vero file system
type RealFileSystem struct{}

func (fs *RealFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (fs *RealFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (fs *RealFileSystem) Open(name string) (*os.File, error) {
	return os.Open(name)
}

func (fs *RealFileSystem) Create(name string) (*os.File, error) {
	return os.Create(name)
}

func (fs *RealFileSystem) Remove(name string) error {
	return os.Remove(name)
}

func (fs *RealFileSystem) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (fs *RealFileSystem) ReadDir(dirname string) ([]os.DirEntry, error) {
	return os.ReadDir(dirname)
}

func (fs *RealFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

// DownloadConfig contains MaxMind download configuration
type DownloadConfig struct {
	LicenseKey string
	EditionID  string // "GeoLite2-Country" or similar
	Timeout    time.Duration
	HTTPClient HTTPClient    // Inject HTTP client
	FileSystem FileSystem    // Inject file system
	BaseURL    string        // Allow custom URL for testing
	DBPath     string        // Allow custom path for testing
	DBFilename string        // Allow custom filename for testing
}

// DefaultDownloadConfig returns default configuration
func DefaultDownloadConfig(licenseKey string) *DownloadConfig {
	return &DownloadConfig{
		LicenseKey: licenseKey,
		EditionID:  "GeoLite2-Country",
		Timeout:    30 * time.Second,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		FileSystem: &RealFileSystem{},
		BaseURL:    maxmindDownloadURL,
		DBPath:     dbPath,
		DBFilename: databaseFilename,
	}
}

// Downloader gestisce il download e l'estrazione del database MaxMind
type Downloader struct {
	config *DownloadConfig
	fs     FileSystem
}

// NewDownloader crea un nuovo Downloader
func NewDownloader(config *DownloadConfig) *Downloader {
	if config.FileSystem == nil {
		config.FileSystem = &RealFileSystem{}
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: config.Timeout}
	}
	if config.BaseURL == "" {
		config.BaseURL = maxmindDownloadURL
	}
	if config.DBPath == "" {
		config.DBPath = dbPath
	}
	if config.DBFilename == "" {
		config.DBFilename = databaseFilename
	}

	return &Downloader{
		config: config,
		fs:     config.FileSystem,
	}
}

// Download downloads the MaxMind GeoLite2 database
func (d *Downloader) Download() error {
	if d.config.LicenseKey == "" {
		return fmt.Errorf("MaxMind license key is required. Get it from https://www.maxmind.com/en/geolite2/signup")
	}

	// Create geoip directory if it doesn't exist
	if err := d.fs.MkdirAll(d.config.DBPath, 0755); err != nil {
		return fmt.Errorf("failed to create geoip directory: %w", err)
	}

	dbFilePath := filepath.Join(d.config.DBPath, d.config.DBFilename)

	// Check if database already exists locally - skip download if present
	if d.fileExists(dbFilePath) {
		info, err := d.fs.Stat(dbFilePath)
		if err == nil && info.Size() > 0 {
			// Database exists and has content - use it
			logger.Log.WithFields(map[string]interface{}{
				"path":     dbFilePath,
				"size":     info.Size(),
				"modified": info.ModTime().Format("2006-01-02 15:04:05 MST"),
			}).Info("Using existing MaxMind database")
			return nil
		}
	}

	// For production/CI environments, check if database is fresh (within 7 days)
	if d.fileExists(dbFilePath) && d.isFileRecent(dbFilePath, 7*24*time.Hour) {
		logger.Log.Info("MaxMind database exists and is recent (< 7 days), skipping download")
		return nil
	}

	// Download the database
	url := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=tar.gz",
		d.config.BaseURL, d.config.EditionID, d.config.LicenseKey)

	resp, err := d.config.HTTPClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Save the tar.gz and extract it
	tarPath := filepath.Join(d.config.DBPath, "geolite2.tar.gz")
	out, err := d.fs.Create(tarPath)
	if err != nil {
		return fmt.Errorf("failed to create tar.gz file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write tar.gz file: %w", err)
	}

	// Extract tar.gz
	if err := d.extractTarGz(tarPath, d.config.DBPath); err != nil {
		return fmt.Errorf("failed to extract database: %w", err)
	}

	// Find and move the mmdb file to the correct location
	mmdbPath, err := d.findMMDBFile(d.config.DBPath)
	if err != nil {
		return fmt.Errorf("failed to find mmdb file: %w", err)
	}

	if mmdbPath != dbFilePath {
		if err := d.fs.Rename(mmdbPath, dbFilePath); err != nil {
			return fmt.Errorf("failed to move mmdb file: %w", err)
		}
	}

	// Cleanup
	d.fs.Remove(tarPath)
	d.cleanupExtractedDirs(d.config.DBPath)

	return nil
}

// fileExists checks if a file exists
func (d *Downloader) fileExists(filepath string) bool {
	_, err := d.fs.Stat(filepath)
	return err == nil
}

// isFileRecent checks if a file is recent (modified within duration)
func (d *Downloader) isFileRecent(filepath string, duration time.Duration) bool {
	info, err := d.fs.Stat(filepath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < duration
}

// extractTarGz extracts a tar.gz file
func (d *Downloader) extractTarGz(tarPath, destPath string) error {
	file, err := d.fs.Open(tarPath)
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
			if err := d.fs.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := d.fs.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
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
func (d *Downloader) findMMDBFile(searchPath string) (string, error) {
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
func (d *Downloader) cleanupExtractedDirs(basePath string) error {
	entries, err := d.fs.ReadDir(basePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
			// Only remove GeoLite2-* directories
			if len(entry.Name()) >= 8 && entry.Name()[:8] == "GeoLite2" {
				d.fs.Remove(filepath.Join(basePath, entry.Name()))
			}
		}
	}

	return nil
}

// DownloadDatabase è la funzione legacy per compatibilità backward
func DownloadDatabase(config *DownloadConfig) error {
	downloader := NewDownloader(config)
	return downloader.Download()
}

// Funzioni di utilità esportate per backwards compatibility
func IsFileRecent(filepath string, duration time.Duration) bool {
	info, err := os.Stat(filepath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < duration
}

func FileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}
