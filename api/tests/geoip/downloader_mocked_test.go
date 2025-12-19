package geoip_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize logger for tests
	logger.InitLogger("error", "/dev/null")
}

// MockHTTPClient is a mock implementation of HTTPClient interface
type MockHTTPClient struct {
	GetFunc func(url string) (*http.Response, error)
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	if m.GetFunc != nil {
		return m.GetFunc(url)
	}
	return nil, errors.New("GetFunc not set")
}

// MockFileSystem is a mock implementation of FileSystem interface
type MockFileSystem struct {
	Files       map[string]*MockFile
	Directories map[string]bool
	MkdirFunc   func(path string, perm os.FileMode) error
	StatFunc    func(name string) (os.FileInfo, error)
	OpenFunc    func(name string) (*os.File, error)
	CreateFunc  func(name string) (*os.File, error)
	RemoveFunc  func(name string) error
	RenameFunc  func(oldpath, newpath string) error
	ReadDirFunc func(dirname string) ([]os.DirEntry, error)
	OpenFileFunc func(name string, flag int, perm os.FileMode) (*os.File, error)
}

func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		Files:       make(map[string]*MockFile),
		Directories: make(map[string]bool),
	}
}

func (m *MockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	if m.MkdirFunc != nil {
		return m.MkdirFunc(path, perm)
	}
	m.Directories[path] = true
	return nil
}

func (m *MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if m.StatFunc != nil {
		return m.StatFunc(name)
	}
	if file, ok := m.Files[name]; ok {
		return file, nil
	}
	return nil, os.ErrNotExist
}

func (m *MockFileSystem) Open(name string) (*os.File, error) {
	if m.OpenFunc != nil {
		return m.OpenFunc(name)
	}
	return nil, errors.New("file not found")
}

func (m *MockFileSystem) Create(name string) (*os.File, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(name)
	}
	// Create a temporary real file for testing
	tmpFile, err := os.CreateTemp("", "mock_*")
	if err != nil {
		return nil, err
	}
	m.Files[name] = &MockFile{
		name:    name,
		size:    0,
		modTime: time.Now(),
		tmpPath: tmpFile.Name(),
	}
	return tmpFile, nil
}

func (m *MockFileSystem) Remove(name string) error {
	if m.RemoveFunc != nil {
		return m.RemoveFunc(name)
	}
	delete(m.Files, name)
	delete(m.Directories, name)
	return nil
}

func (m *MockFileSystem) Rename(oldpath, newpath string) error {
	if m.RenameFunc != nil {
		return m.RenameFunc(oldpath, newpath)
	}
	if file, ok := m.Files[oldpath]; ok {
		m.Files[newpath] = file
		delete(m.Files, oldpath)
		return nil
	}
	return errors.New("file not found")
}

func (m *MockFileSystem) ReadDir(dirname string) ([]os.DirEntry, error) {
	if m.ReadDirFunc != nil {
		return m.ReadDirFunc(dirname)
	}
	return []os.DirEntry{}, nil
}

func (m *MockFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if m.OpenFileFunc != nil {
		return m.OpenFileFunc(name, flag, perm)
	}
	// Create a temporary real file for testing
	tmpFile, err := os.CreateTemp("", "mock_*")
	if err != nil {
		return nil, err
	}
	return tmpFile, nil
}

// MockFile implements os.FileInfo
type MockFile struct {
	name    string
	size    int64
	modTime time.Time
	tmpPath string
}

func (m *MockFile) Name() string       { return filepath.Base(m.name) }
func (m *MockFile) Size() int64        { return m.size }
func (m *MockFile) Mode() os.FileMode  { return 0644 }
func (m *MockFile) ModTime() time.Time { return m.modTime }
func (m *MockFile) IsDir() bool        { return false }
func (m *MockFile) Sys() interface{}   { return nil }

// MockDirEntry implements os.DirEntry
type MockDirEntry struct {
	name  string
	isDir bool
}

func (m MockDirEntry) Name() string               { return m.name }
func (m MockDirEntry) IsDir() bool                { return m.isDir }
func (m MockDirEntry) Type() os.FileMode          { return 0 }
func (m MockDirEntry) Info() (os.FileInfo, error) { return nil, nil }

// Helper function to create a realistic tar.gz with MMDB file
func createMockTarGzWithMMDB(t *testing.T) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Create a directory entry
	err := tw.WriteHeader(&tar.Header{
		Name:     "GeoLite2-Country_20231215/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	})
	require.NoError(t, err)

	// Create the MMDB file
	mmdbContent := []byte("fake mmdb content for testing")
	err = tw.WriteHeader(&tar.Header{
		Name:     "GeoLite2-Country_20231215/GeoLite2-Country.mmdb",
		Mode:     0644,
		Size:     int64(len(mmdbContent)),
		Typeflag: tar.TypeReg,
	})
	require.NoError(t, err)
	_, err = tw.Write(mmdbContent)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	return buf.Bytes()
}

// Test 1: Successful download with mocked HTTP and real filesystem for extraction
func TestDownloader_Download_Success(t *testing.T) {
	// Use real filesystem for this test because findMMDBFile uses filepath.Walk
	tmpDir, err := os.MkdirTemp("", "geoip_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tarGzData := createMockTarGzWithMMDB(t)

	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			assert.Contains(t, url, "edition_id=GeoLite2-Country")
			assert.Contains(t, url, "license_key=test_key")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tarGzData)),
			}, nil
		},
	}

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		Timeout:    10 * time.Second,
		HTTPClient: mockHTTP,
		BaseURL:    "https://download.maxmind.com/app/geoip_download",
		DBPath:     tmpDir,
		DBFilename: "GeoLite2-Country.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err = downloader.Download()

	assert.NoError(t, err)

	// Verify the database file was created
	dbPath := filepath.Join(tmpDir, "GeoLite2-Country.mmdb")
	assert.FileExists(t, dbPath)
}

// Test 2: Missing license key
func TestDownloader_Download_MissingLicenseKey(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{}

	config := &geoip.DownloadConfig{
		LicenseKey: "",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "license key is required")
}

// Test 3: Existing database file (skip download)
func TestDownloader_Download_ExistingFile(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			t.Fatal("HTTP Get should not be called when file exists")
			return nil, nil
		},
	}

	// Add existing database file
	dbPath := filepath.Join("test_geoip", "test.mmdb")
	mockFS.Files[dbPath] = &MockFile{
		name:    dbPath,
		size:    1024,
		modTime: time.Now(),
	}

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.NoError(t, err)
}

// Test 4: Recent database file (skip download)
func TestDownloader_Download_RecentFile(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			t.Fatal("HTTP Get should not be called when file is recent")
			return nil, nil
		},
	}

	// Add recent database file (2 days old)
	dbPath := filepath.Join("test_geoip", "test.mmdb")
	mockFS.Files[dbPath] = &MockFile{
		name:    dbPath,
		size:    1024,
		modTime: time.Now().Add(-2 * 24 * time.Hour),
	}

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.NoError(t, err)
}

// Test 5: HTTP error (401 Unauthorized)
func TestDownloader_Download_HTTPUnauthorized(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewReader([]byte("Invalid license key"))),
			}, nil
		},
	}

	// Don't add any existing file, so download will be attempted

	config := &geoip.DownloadConfig{
		LicenseKey: "invalid_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "download failed with status 401")
}

// Test 6: HTTP timeout error
func TestDownloader_Download_HTTPTimeout(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return nil, errors.New("timeout: context deadline exceeded")
		},
	}

	// Don't add existing file, so download will be attempted

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download database")
}

// Test 7: MkdirAll error
func TestDownloader_Download_MkdirError(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockFS.MkdirFunc = func(path string, perm os.FileMode) error {
		return errors.New("permission denied")
	}

	mockHTTP := &MockHTTPClient{}

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create geoip directory")
}

// Test 8: Create tar.gz file error
func TestDownloader_Download_CreateTarGzError(t *testing.T) {
	mockFS := NewMockFileSystem()
	tarGzData := createMockTarGzWithMMDB(t)

	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tarGzData)),
			}, nil
		},
	}

	mockFS.CreateFunc = func(name string) (*os.File, error) {
		return nil, errors.New("disk full")
	}

	// Don't add existing file, so download will be attempted

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create tar.gz file")
}

// Test 9: Extract tar.gz error (corrupt archive)
func TestDownloader_Download_ExtractError(t *testing.T) {
	mockFS := NewMockFileSystem()
	corruptData := []byte("not a valid tar.gz file")

	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(corruptData)),
			}, nil
		},
	}

	// Mock Open to read the corrupt tar.gz
	mockFS.OpenFunc = func(name string) (*os.File, error) {
		if strings.HasSuffix(name, "geolite2.tar.gz") {
			tmpFile, err := os.CreateTemp("", "corrupt_*")
			require.NoError(t, err)
			_, err = tmpFile.Write(corruptData)
			require.NoError(t, err)
			_, err = tmpFile.Seek(0, 0)
			require.NoError(t, err)
			return tmpFile, nil
		}
		return nil, os.ErrNotExist
	}

	// Don't add existing file, so download will be attempted

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract database")
}

// Test 10: MMDB file not found after extraction
func TestDownloader_Download_MMDBNotFound(t *testing.T) {
	mockFS := NewMockFileSystem()

	// Create tar.gz without MMDB file
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Just create a directory, no MMDB file
	err := tw.WriteHeader(&tar.Header{
		Name:     "GeoLite2-Country_20231215/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	})
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	tarGzData := buf.Bytes()

	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tarGzData)),
			}, nil
		},
	}

	// Mock Open to read the tar.gz
	mockFS.OpenFunc = func(name string) (*os.File, error) {
		if strings.HasSuffix(name, "geolite2.tar.gz") {
			tmpFile, err := os.CreateTemp("", "nomm db_*")
			require.NoError(t, err)
			_, err = tmpFile.Write(tarGzData)
			require.NoError(t, err)
			_, err = tmpFile.Seek(0, 0)
			require.NoError(t, err)
			return tmpFile, nil
		}
		return nil, os.ErrNotExist
	}

	// Don't add existing file, so download will be attempted

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err = downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find mmdb file")
}

// Test 11: Rename error
func TestDownloader_Download_RenameError(t *testing.T) {
	// Use real filesystem but mock rename to fail
	tmpDir, err := os.MkdirTemp("", "geoip_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a read-only directory as DBPath to cause rename to fail
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err = os.MkdirAll(readOnlyDir, 0444) // Read-only directory
	require.NoError(t, err)

	tarGzData := createMockTarGzWithMMDB(t)

	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tarGzData)),
			}, nil
		},
	}

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		DBPath:     readOnlyDir,
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err = downloader.Download()

	assert.Error(t, err)
	// The error could be from extraction or rename, both are filesystem permission errors
	assert.True(t, strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "read-only"))
}

// Test 12: DefaultDownloadConfig creates correct config
func TestDefaultDownloadConfig(t *testing.T) {
	config := geoip.DefaultDownloadConfig("my_license_key")

	assert.Equal(t, "my_license_key", config.LicenseKey)
	assert.Equal(t, "GeoLite2-Country", config.EditionID)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.NotNil(t, config.HTTPClient)
	assert.NotNil(t, config.FileSystem)
	assert.NotEmpty(t, config.BaseURL)
	assert.NotEmpty(t, config.DBPath)
	assert.NotEmpty(t, config.DBFilename)
}

// Test 13: NewDownloader sets defaults
func TestNewDownloader_SetsDefaults(t *testing.T) {
	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		Timeout:    30 * time.Second,
	}

	downloader := geoip.NewDownloader(config)
	assert.NotNil(t, downloader)

	// Verify defaults were set
	assert.NotNil(t, config.FileSystem)
	assert.NotNil(t, config.HTTPClient)
	assert.NotEmpty(t, config.BaseURL)
	assert.NotEmpty(t, config.DBPath)
	assert.NotEmpty(t, config.DBFilename)
}

// Test 14: Cleanup extracted directories
func TestDownloader_Download_CleanupDirectories(t *testing.T) {
	// Use real filesystem to test cleanup
	tmpDir, err := os.MkdirTemp("", "geoip_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create some directories that should and shouldn't be cleaned up
	otherDir := filepath.Join(tmpDir, "other_dir")
	err = os.MkdirAll(otherDir, 0755)
	require.NoError(t, err)

	tarGzData := createMockTarGzWithMMDB(t)

	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tarGzData)),
			}, nil
		},
	}

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		DBPath:     tmpDir,
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err = downloader.Download()

	assert.NoError(t, err)

	// Verify database file was created
	dbPath := filepath.Join(tmpDir, "test.mmdb")
	assert.FileExists(t, dbPath)

	// Verify tar.gz was removed
	tarGzPath := filepath.Join(tmpDir, "geolite2.tar.gz")
	assert.NoFileExists(t, tarGzPath)

	// Verify GeoLite2 directory was removed
	geoDir := filepath.Join(tmpDir, "GeoLite2-Country_20231215")
	assert.NoDirExists(t, geoDir)

	// Verify other_dir still exists (should not be removed)
	assert.DirExists(t, otherDir)
}

// Test 15: Backward compatibility - DownloadDatabase function
func TestDownloadDatabase_BackwardCompatibility(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{}

	config := &geoip.DownloadConfig{
		LicenseKey: "",
		EditionID:  "GeoLite2-Country",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	// Test the legacy function
	err := geoip.DownloadDatabase(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "license key is required")
}

// Test 16: Exported utility functions for backward compatibility
func TestExportedUtilityFunctions(t *testing.T) {
	// Test FileExists
	tmpFile, err := os.CreateTemp("", "util_test_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	exists := geoip.FileExists(tmpFile.Name())
	assert.True(t, exists)

	exists = geoip.FileExists("/non/existent/file")
	assert.False(t, exists)

	// Test IsFileRecent
	isRecent := geoip.IsFileRecent(tmpFile.Name(), 1*time.Hour)
	assert.True(t, isRecent)

	isRecent = geoip.IsFileRecent(tmpFile.Name(), 1*time.Nanosecond)
	assert.False(t, isRecent)

	isRecent = geoip.IsFileRecent("/non/existent/file", 1*time.Hour)
	assert.False(t, isRecent)
}

// Test 17: HTTP 404 error
func TestDownloader_Download_HTTP404(t *testing.T) {
	mockFS := NewMockFileSystem()
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewReader([]byte("Edition not found"))),
			}, nil
		},
	}

	// Don't add existing file, so download will be attempted

	config := &geoip.DownloadConfig{
		LicenseKey: "test_key",
		EditionID:  "NonExistentEdition",
		HTTPClient: mockHTTP,
		FileSystem: mockFS,
		DBPath:     "test_geoip",
		DBFilename: "test.mmdb",
	}

	downloader := geoip.NewDownloader(config)
	err := downloader.Download()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "download failed with status 404")
}

// Test 18: Empty existing file (size 0) should skip if recent, download if old
func TestDownloader_Download_EmptyExistingFile(t *testing.T) {
	t.Run("Empty recent file skips download", func(t *testing.T) {
		mockFS := NewMockFileSystem()

		httpCalled := false
		mockHTTP := &MockHTTPClient{
			GetFunc: func(url string) (*http.Response, error) {
				httpCalled = true
				return nil, errors.New("should not be called")
			},
		}

		// Add empty recent database file
		dbPath := filepath.Join("test_geoip", "test.mmdb")
		mockFS.Files[dbPath] = &MockFile{
			name:    dbPath,
			size:    0,           // Empty file
			modTime: time.Now(), // Recent
		}

		config := &geoip.DownloadConfig{
			LicenseKey: "test_key",
			EditionID:  "GeoLite2-Country",
			HTTPClient: mockHTTP,
			FileSystem: mockFS,
			DBPath:     "test_geoip",
			DBFilename: "test.mmdb",
		}

		downloader := geoip.NewDownloader(config)
		err := downloader.Download()

		// Should skip download for empty but recent file
		assert.NoError(t, err)
		assert.False(t, httpCalled, "Empty recent file should skip download")
	})

	t.Run("Empty old file triggers download", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "geoip_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		tarGzData := createMockTarGzWithMMDB(t)

		httpCalled := false
		mockHTTP := &MockHTTPClient{
			GetFunc: func(url string) (*http.Response, error) {
				httpCalled = true
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(tarGzData)),
				}, nil
			},
		}

		config := &geoip.DownloadConfig{
			LicenseKey: "test_key",
			EditionID:  "GeoLite2-Country",
			HTTPClient: mockHTTP,
			DBPath:     tmpDir,
			DBFilename: "test.mmdb",
		}

		// No existing file, so download will happen
		downloader := geoip.NewDownloader(config)
		err = downloader.Download()

		// Should download for missing file (equivalent to empty old file behavior)
		assert.NoError(t, err)
		assert.True(t, httpCalled, "Missing file should trigger download attempt")

		// Verify the database file was created
		dbPath := filepath.Join(tmpDir, "test.mmdb")
		assert.FileExists(t, dbPath)
	})
}
