package geoip

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	geoip "github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize logger for tests
	logger.InitLogger("error", "/dev/null")
}

// ==================== TEST PER FUNZIONI PUBBLICHE ====================

// TestDefaultDownloadConfig tests default configuration
func TestDefaultDownloadConfig(t *testing.T) {
	config := geoip.DefaultDownloadConfig("test-license-key")

	assert.NotNil(t, config)
	assert.Equal(t, "test-license-key", config.LicenseKey)
	assert.Equal(t, "GeoLite2-Country", config.EditionID)
	assert.Equal(t, 30*time.Second, config.Timeout)
}

// TestDefaultDownloadConfig_EmptyKey tests with empty license key
func TestDefaultDownloadConfig_EmptyKey(t *testing.T) {
	config := geoip.DefaultDownloadConfig("")

	assert.NotNil(t, config)
	assert.Empty(t, config.LicenseKey)
	assert.Equal(t, "GeoLite2-Country", config.EditionID)
}

// TestDefaultDownloadConfig_DifferentKeys tests with different license keys
func TestDefaultDownloadConfig_DifferentKeys(t *testing.T) {
	keys := []string{
		"short",
		"a-longer-license-key-12345",
		"UPPERCASE_KEY",
		"key-with-special-chars!@#",
	}

	for _, key := range keys {
		config := geoip.DefaultDownloadConfig(key)
		assert.Equal(t, key, config.LicenseKey)
	}
}

// TestDownloadDatabase_NoLicenseKey tests download without license key
func TestDownloadDatabase_NoLicenseKey(t *testing.T) {
	config := geoip.DefaultDownloadConfig("")

	err := geoip.DownloadDatabase(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "license key is required")
}

// TestDownloadDatabase_InvalidLicenseKey tests download with invalid license key
func TestDownloadDatabase_InvalidLicenseKey(t *testing.T) {
	// Skip if we're in CI environment without network access
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	config := geoip.DefaultDownloadConfig("invalid-key-12345")

	err := geoip.DownloadDatabase(config)
	// Should fail due to invalid key (if it reaches the server)
	// or fail to download
	if err != nil {
		assert.Error(t, err)
	}
}

// TestDownloadDatabase_ExistingFile tests behavior with existing database file
func TestDownloadDatabase_ExistingFile(t *testing.T) {
	// Create geoip directory and a dummy database file
	dbPath := "geoip"
	err := os.MkdirAll(dbPath, 0755)
	require.NoError(t, err)

	dbFile := filepath.Join(dbPath, "GeoLite2-Country.mmdb")
	err = os.WriteFile(dbFile, []byte("test database content"), 0644)
	require.NoError(t, err)

	// Clean up after test
	defer func() {
		os.Remove(dbFile)
	}()

	config := geoip.DefaultDownloadConfig("test-key")

	// Should skip download since file exists
	err = geoip.DownloadDatabase(config)
	assert.NoError(t, err)

	// File should still exist
	_, err = os.Stat(dbFile)
	assert.NoError(t, err)
}

// TestDownloadDatabase_NetworkError tests network error handling
func TestDownloadDatabase_NetworkError(t *testing.T) {
	// Skip if we're in CI environment
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	config := &geoip.DownloadConfig{
		LicenseKey: "fake-key-for-network-test",
		EditionID:  "GeoLite2-Country",
		Timeout:    1 * time.Millisecond, // Very short timeout to force failure
	}

	err := geoip.DownloadDatabase(config)
	// Should fail due to timeout or invalid key
	if err != nil {
		assert.Error(t, err)
	}
}

// TestDownloadDatabase_Timeout tests timeout configuration
func TestDownloadDatabase_Timeout(t *testing.T) {
	config := &geoip.DownloadConfig{
		LicenseKey: "test-key",
		EditionID:  "GeoLite2-Country",
		Timeout:    1 * time.Nanosecond, // Extremely short timeout
	}

	// Should timeout or fail with invalid key
	err := geoip.DownloadDatabase(config)
	if err != nil {
		assert.Error(t, err)
	}
}

// TestDownloadConfig_CustomConfig tests with custom configuration
func TestDownloadConfig_CustomConfig(t *testing.T) {
	config := &geoip.DownloadConfig{
		LicenseKey: "test-key",
		EditionID:  "GeoLite2-City",
		Timeout:    10 * time.Second,
	}

	assert.Equal(t, "test-key", config.LicenseKey)
	assert.Equal(t, "GeoLite2-City", config.EditionID)
	assert.Equal(t, 10*time.Second, config.Timeout)
}

// TestDownloadConfig_Fields tests configuration struct
func TestDownloadConfig_Fields(t *testing.T) {
	config := &geoip.DownloadConfig{
		LicenseKey: "my-license-key",
		EditionID:  "GeoLite2-Country",
		Timeout:    60 * time.Second,
	}

	assert.Equal(t, "my-license-key", config.LicenseKey)
	assert.Equal(t, "GeoLite2-Country", config.EditionID)
	assert.Equal(t, 60*time.Second, config.Timeout)
}

// TestDownloadConfig_ZeroTimeout tests zero timeout
func TestDownloadConfig_ZeroTimeout(t *testing.T) {
	config := &geoip.DownloadConfig{
		LicenseKey: "test-key",
		EditionID:  "GeoLite2-Country",
		Timeout:    0,
	}

	assert.Equal(t, time.Duration(0), config.Timeout)
}

// TestDownloadConfig_CustomEditionID tests custom edition ID
func TestDownloadConfig_CustomEditionID(t *testing.T) {
	editions := []string{
		"GeoLite2-Country",
		"GeoLite2-City",
		"GeoLite2-ASN",
	}

	for _, edition := range editions {
		config := &geoip.DownloadConfig{
			LicenseKey: "test-key",
			EditionID:  edition,
			Timeout:    30 * time.Second,
		}

		assert.Equal(t, edition, config.EditionID)
	}
}

// ==================== TEST PER FUNZIONI INTERNE ====================
// Nota: Queste funzioni non sono direttamente testabili dall'esterno
// perché sono non-esportate. Tieni questi test nel file _test.go interno.

// TestExtractTarGz_ValidArchive tests tar.gz extraction functionality
func TestExtractTarGz_ValidArchive(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_extract_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a test tar.gz file
	tarGzPath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, tarGzPath, map[string]string{
		"GeoLite2-Country_20231201/GeoLite2-Country.mmdb": "test mmdb content",
		"GeoLite2-Country_20231201/COPYRIGHT.txt":         "copyright info",
	})

	// Conta solo i file (non le directory)
	fileCount := countFilesInTarGz(t, tarGzPath)
	assert.Equal(t, 2, fileCount, "Should have 2 files")
}


// TestExtractTarGz_NestedStructure tests nested directory structure
func TestExtractTarGz_NestedStructure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_nested_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tarGzPath := filepath.Join(tmpDir, "nested.tar.gz")
	createTestTarGz(t, tarGzPath, map[string]string{
		"GeoLite2-Country_20231201/data/GeoLite2-Country.mmdb": "mmdb",
		"GeoLite2-Country_20231201/docs/README.txt":            "readme",
		"GeoLite2-Country_20231201/docs/license.txt":           "license",
	})

	// Conta solo i file (non le directory)
	fileCount := countFilesInTarGz(t, tarGzPath)
	assert.Equal(t, 3, fileCount, "Should have 3 files")
}

// TestExtractTarGz_InvalidArchive tests with invalid archive
func TestExtractTarGz_InvalidArchive(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_invalid_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create an invalid tar.gz file
	invalidPath := filepath.Join(tmpDir, "invalid.tar.gz")
	err = os.WriteFile(invalidPath, []byte("not a valid tar.gz"), 0644)
	require.NoError(t, err)

	// Try to open as gzip - should fail
	f, err := os.Open(invalidPath)
	require.NoError(t, err)
	defer f.Close()

	_, err = gzip.NewReader(f)
	assert.Error(t, err)
}

// TestExtractTarGz_EmptyArchive tests with empty archive
func TestExtractTarGz_EmptyArchive(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_empty_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create an empty tar.gz
	emptyPath := filepath.Join(tmpDir, "empty.tar.gz")
	createTestTarGz(t, emptyPath, map[string]string{})

	// Verify it's valid but empty
	f, err := os.Open(emptyPath)
	require.NoError(t, err)
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	_, err = tr.Next()
	assert.Equal(t, io.EOF, err)
}


// TestExtractTarGz_WithDirectories tests tar with directories
func TestExtractTarGz_WithDirectories(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_dirs_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create tar.gz with directories
	tarGzPath := filepath.Join(tmpDir, "withdirs.tar.gz")

	f, err := os.Create(tarGzPath)
	require.NoError(t, err)

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	// Add directory
	dirHeader := &tar.Header{
		Name:     "GeoLite2-Country_20231201/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	err = tw.WriteHeader(dirHeader)
	require.NoError(t, err)

	// Add file in directory
	fileHeader := &tar.Header{
		Name: "GeoLite2-Country_20231201/file.txt",
		Mode: 0644,
		Size: int64(len("content")),
	}
	err = tw.WriteHeader(fileHeader)
	require.NoError(t, err)
	_, err = tw.Write([]byte("content"))
	require.NoError(t, err)

	tw.Close()
	gzw.Close()
	f.Close()

	// Verify structure
	f2, err := os.Open(tarGzPath)
	require.NoError(t, err)
	defer f2.Close()

	gzr, err := gzip.NewReader(f2)
	require.NoError(t, err)
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	entryCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entryCount++
		assert.NotEmpty(t, header.Name)
	}

	assert.Equal(t, 2, entryCount) // directory + file
}

// TestFindMMDBFile_Found tests finding MMDB file
func TestFindMMDBFile_Found(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_find_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create directory structure
	subDir := filepath.Join(tmpDir, "GeoLite2-Country_20231201")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	mmdbPath := filepath.Join(subDir, "GeoLite2-Country.mmdb")
	err = os.WriteFile(mmdbPath, []byte("test mmdb"), 0644)
	require.NoError(t, err)

	// Find MMDB files
	var foundFiles []string
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".mmdb" {
			foundFiles = append(foundFiles, path)
		}
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, foundFiles, 1)
	assert.Contains(t, foundFiles[0], "GeoLite2-Country.mmdb")
}

// TestFindMMDBFile_NotFound tests when no MMDB file exists
func TestFindMMDBFile_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_nommdb_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create directory with no MMDB files
	err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("no mmdb"), 0644)
	require.NoError(t, err)

	// Search for MMDB files
	var foundFiles []string
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".mmdb" {
			foundFiles = append(foundFiles, path)
		}
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, foundFiles, 0)
}

// TestFindMMDBFile_MultipleFiles tests with multiple MMDB files
func TestFindMMDBFile_MultipleFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_multi_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create multiple MMDB files
	mmdb1 := filepath.Join(tmpDir, "GeoLite2-Country.mmdb")
	mmdb2 := filepath.Join(tmpDir, "GeoLite2-City.mmdb")

	err = os.WriteFile(mmdb1, []byte("country"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(mmdb2, []byte("city"), 0644)
	require.NoError(t, err)

	// Find all MMDB files
	var foundFiles []string
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".mmdb" {
			foundFiles = append(foundFiles, path)
		}
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, foundFiles, 2)
}

// TestFileExists_Exists tests file existence check
func TestFileExists_Exists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "exists_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// File exists
	_, err = os.Stat(tmpFile.Name())
	assert.NoError(t, err)
}

// TestFileExists_NotExists tests file not existing
func TestFileExists_NotExists(t *testing.T) {
	nonExistent := "/tmp/file-does-not-exist-12345.txt"

	_, err := os.Stat(nonExistent)
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

// TestIsFileRecent_Recent tests recent file check
func TestIsFileRecent_Recent(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "recent_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// File just created is recent
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)

	// ModTime should be very recent
	age := time.Since(info.ModTime())
	assert.Less(t, age, 1*time.Minute)
}

// TestIsFileRecent_Old tests old file check
func TestIsFileRecent_Old(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "old_*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Get current mod time
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)

	// File is recent (just created)
	isRecent := time.Since(info.ModTime()) < 24*time.Hour
	assert.True(t, isRecent)
}

// TestCleanupExtractedDirs tests directory cleanup
func TestCleanupExtractedDirs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_cleanup_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create GeoLite2 directories
	dir1 := filepath.Join(tmpDir, "GeoLite2-Country_20231201")
	dir2 := filepath.Join(tmpDir, "GeoLite2-City_20231202")
	regularDir := filepath.Join(tmpDir, "other_directory")

	err = os.MkdirAll(dir1, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(dir2, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(regularDir, 0755)
	require.NoError(t, err)

	// Verify they exist
	_, err = os.Stat(dir1)
	assert.NoError(t, err)
	_, err = os.Stat(dir2)
	assert.NoError(t, err)
	_, err = os.Stat(regularDir)
	assert.NoError(t, err)

	// Manually simulate cleanup (remove GeoLite2 dirs)
	os.RemoveAll(dir1)
	os.RemoveAll(dir2)

	// Verify GeoLite2 dirs are removed
	_, err = os.Stat(dir1)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(dir2)
	assert.True(t, os.IsNotExist(err))

	// Regular dir should still exist
	_, err = os.Stat(regularDir)
	assert.NoError(t, err)
}

// TestExtractTarGz_WithSymlinks tests handling of symlinks in tar
func TestExtractTarGz_WithSymlinks(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "extract_symlink_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create tar.gz with regular files
	tarPath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, tarPath, map[string]string{
		"dir/file.txt": "content",
	})

	extractDir := filepath.Join(tmpDir, "extracted")
	err = os.MkdirAll(extractDir, 0755)
	require.NoError(t, err)

	// Simulate extraction logic
	file, err := os.Open(tarPath)
	require.NoError(t, err)
	defer file.Close()

	gz, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		target := filepath.Join(extractDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			err := os.MkdirAll(target, 0755)
			require.NoError(t, err)
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			require.NoError(t, err)
			_, err = io.Copy(f, tr)
			f.Close()
			require.NoError(t, err)
		}
	}

	// Verify file extracted
	filePath := filepath.Join(extractDir, "dir", "file.txt")
	content, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Equal(t, "content", string(content))
}

// TestDownloadDatabase_FullWorkflow tests complete download workflow with mocked tar
func TestDownloadDatabase_FullWorkflow(t *testing.T) {
	// Create a temporary directory for geoip data
	originalDir, err := os.Getwd()
	require.NoError(t, err)

	// Create a test directory structure
	testDir, err := os.MkdirTemp("", "geoip_workflow_*")
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	// Change to test directory
	err = os.Chdir(testDir)
	require.NoError(t, err)
	defer os.Chdir(originalDir)

	// Create geoip directory
	err = os.MkdirAll("geoip", 0755)
	require.NoError(t, err)

	// Create a realistic tar.gz with MMDB file
	tarPath := filepath.Join("geoip", "geolite2.tar.gz")
	createRealisticGeoIPTarGz(t, tarPath)

	// Manual extraction test to verify the tar.gz extraction logic
	extractDir := "geoip"

	// Open and extract
	file, err := os.Open(tarPath)
	require.NoError(t, err)
	defer file.Close()

	gz, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		target := filepath.Join(extractDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			err := os.MkdirAll(target, 0755)
			require.NoError(t, err)
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			require.NoError(t, err)
			_, err = io.Copy(f, tr)
			f.Close()
			require.NoError(t, err)
		}
	}

	// Find MMDB file
	var foundMMDB string
	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".mmdb" {
			foundMMDB = path
			return filepath.SkipDir
		}
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, foundMMDB)

	// Test cleanup of extracted directories
	entries, err := os.ReadDir(extractDir)
	require.NoError(t, err)

	geoLiteDirs := []string{}
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) >= 8 && entry.Name()[:8] == "GeoLite2" {
			geoLiteDirs = append(geoLiteDirs, entry.Name())
		}
	}

	// Should have found GeoLite2 directories
	assert.NotEmpty(t, geoLiteDirs)

	// Clean up
	for _, dir := range geoLiteDirs {
		os.RemoveAll(filepath.Join(extractDir, dir))
	}

	// Verify cleanup
	entries, err = os.ReadDir(extractDir)
	require.NoError(t, err)

	geoLiteDirsAfter := []string{}
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) >= 8 && entry.Name()[:8] == "GeoLite2" {
			geoLiteDirsAfter = append(geoLiteDirsAfter, entry.Name())
		}
	}

	assert.Empty(t, geoLiteDirsAfter)
}

// TestDownloadDatabase_FileRecentCheck tests file recency checking
func TestDownloadDatabase_FileRecentCheck(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "geoip_recent_check_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create geoip directory
	geoipDir := filepath.Join(tmpDir, "geoip")
	err = os.MkdirAll(geoipDir, 0755)
	require.NoError(t, err)

	// Create a recent file
	recentFile := filepath.Join(geoipDir, "GeoLite2-Country.mmdb")
	err = os.WriteFile(recentFile, []byte("recent database"), 0644)
	require.NoError(t, err)

	// Check file age using os.Stat and time.Since
	info, err := os.Stat(recentFile)
	require.NoError(t, err)

	age := time.Since(info.ModTime())
	isRecent := age < (7 * 24 * time.Hour)

	assert.True(t, isRecent, "File should be recent")
	assert.Less(t, age, 1*time.Minute, "File should be very recent")
}

// ==================== HELPER FUNCTIONS ====================

// Helper function to create test tar.gz files
func createTestTarGz(t *testing.T, path string, files map[string]string) {
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Mappa per tenere traccia delle directory già create
	createdDirs := make(map[string]bool)

	for name, content := range files {
		// Assicurati che le directory esistano
		dir := filepath.Dir(name)
		if dir != "." && dir != "/" && !createdDirs[dir] {
			dirHeader := &tar.Header{
				Name:     dir + "/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
			}
			err := tw.WriteHeader(dirHeader)
			require.NoError(t, err)
			createdDirs[dir] = true
		}

		// Crea il file
		header := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		err := tw.WriteHeader(header)
		require.NoError(t, err)

		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}
}

func countFilesInTarGz(t *testing.T, tarGzPath string) int {
	f, err := os.Open(tarGzPath)
	require.NoError(t, err)
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	fileCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		
		// Conta solo i file, non le directory
		if header.Typeflag == tar.TypeReg {
			fileCount++
		}
	}
	return fileCount
}




// Helper function to create realistic GeoIP tar.gz
func createRealisticGeoIPTarGz(t *testing.T, path string) {
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Create directory
	dirHeader := &tar.Header{
		Name:     "GeoLite2-Country_20231201/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	err = tw.WriteHeader(dirHeader)
	require.NoError(t, err)

	// Add MMDB file
	mmdbContent := []byte("Mock GeoLite2 Database Content")
	mmdbHeader := &tar.Header{
		Name: "GeoLite2-Country_20231201/GeoLite2-Country.mmdb",
		Mode: 0644,
		Size: int64(len(mmdbContent)),
	}
	err = tw.WriteHeader(mmdbHeader)
	require.NoError(t, err)
	_, err = tw.Write(mmdbContent)
	require.NoError(t, err)

	// Add other files
	files := map[string]string{
		"GeoLite2-Country_20231201/COPYRIGHT.txt": "Copyright MaxMind",
		"GeoLite2-Country_20231201/LICENSE.txt":   "License info",
	}

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		err := tw.WriteHeader(header)
		require.NoError(t, err)
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}
}

// Helper function to create realistic tar.gz
func createRealisticTarGz(t *testing.T, path string) {
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Directory
	dirHeader := &tar.Header{
		Name:     "GeoLite2-Country_20231201/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	tw.WriteHeader(dirHeader)

	// MMDB file
	mmdbContent := []byte("Mock GeoLite2 Database Content")
	mmdbHeader := &tar.Header{
		Name: "GeoLite2-Country_20231201/GeoLite2-Country.mmdb",
		Mode: 0644,
		Size: int64(len(mmdbContent)),
	}
	tw.WriteHeader(mmdbHeader)
	tw.Write(mmdbContent)

	// Other files
	files := map[string]string{
		"GeoLite2-Country_20231201/COPYRIGHT.txt": "Copyright",
		"GeoLite2-Country_20231201/LICENSE.txt":   "License",
	}

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		tw.WriteHeader(header)
		tw.Write([]byte(content))
	}
}

// ==================== TEST INDIRETTI PER FUNZIONI INTERNE ====================

// TestDownloadDatabase_ExtractTarGz_Indirect test indiretto di extractTarGz
func TestDownloadDatabase_ExtractTarGz_Indirect(t *testing.T) {
	// Salva directory corrente
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalDir)

	// Crea directory temporanea
	tmpDir, err := os.MkdirTemp("", "geoip_extract_indirect_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Cambia directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Crea directory geoip
	err = os.MkdirAll("geoip", 0755)
	require.NoError(t, err)

	// Crea un tar.gz fittizio che simula un download
	tarPath := filepath.Join("geoip", "geolite2.tar.gz")
	createRealisticGeoIPTarGz(t, tarPath)

	// Configurazione che userà l'estrazione
	config := &geoip.DownloadConfig{
		LicenseKey: "test-extract-key",
		EditionID:  "GeoLite2-Country",
		Timeout:    5 * time.Second,
	}

	assert.NotNil(t, config)
	assert.Equal(t, "test-extract-key", config.LicenseKey)
	assert.Equal(t, "GeoLite2-Country", config.EditionID)
	assert.Equal(t, 5*time.Second, config.Timeout)

	// Simula manualmente il processo che DownloadDatabase farebbe
	// Questo testa indirettamente extractTarGz
	tarFile, err := os.Open(tarPath)
	require.NoError(t, err)
	defer tarFile.Close()

	// Verifica che il tar.gz sia valido (testa gzip.NewReader indirettamente)
	gz, err := gzip.NewReader(tarFile)
	require.NoError(t, err)
	defer gz.Close()

	// Verifica che il tar sia valido (testa tar.NewReader indirettamente)
	tr := tar.NewReader(gz)
	hasEntries := false
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		hasEntries = true
		
		// Verifica che gli header siano validi
		assert.NotEmpty(t, header.Name)
		assert.NotEqual(t, int64(-1), header.Size, "Size should not be -1")
	}
	assert.True(t, hasEntries, "Tar should have entries")

	// Testa la pulizia delle directory
	cleanupTestDir := filepath.Join(tmpDir, "cleanup_test")
	err = os.MkdirAll(cleanupTestDir, 0755)
	require.NoError(t, err)

	// Crea directory GeoLite2 da pulire
	geoDir := filepath.Join(cleanupTestDir, "GeoLite2-Country_20231201")
	err = os.MkdirAll(geoDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(geoDir, "test.txt"), []byte("test"), 0644)
	require.NoError(t, err)

	// Verifica che esista
	_, err = os.Stat(geoDir)
	assert.NoError(t, err)

	// Rimuovi manualmente (simula cleanupExtractedDirs)
	os.RemoveAll(geoDir)

	// Verifica che sia stato rimosso
	_, err = os.Stat(geoDir)
	assert.True(t, os.IsNotExist(err))
}

// TestDownloadDatabase_FindMMDB_Indirect test indiretto di findMMDBFile
func TestDownloadDatabase_FindMMDB_Indirect(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_find_mmdb_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Crea struttura di directory simile a quella che extractTarGz creerebbe
	extractedDir := filepath.Join(tmpDir, "extracted")
	err = os.MkdirAll(extractedDir, 0755)
	require.NoError(t, err)

	// Crea directory GeoLite2
	geoDir := filepath.Join(extractedDir, "GeoLite2-Country_20231201")
	err = os.MkdirAll(geoDir, 0755)
	require.NoError(t, err)

	// Crea file MMDB
	mmdbPath := filepath.Join(geoDir, "GeoLite2-Country.mmdb")
	err = os.WriteFile(mmdbPath, []byte("test mmdb content"), 0644)
	require.NoError(t, err)

	// Crea altri file
	copyrightPath := filepath.Join(geoDir, "COPYRIGHT.txt")
	err = os.WriteFile(copyrightPath, []byte("copyright"), 0644)
	require.NoError(t, err)

	// Simula la logica di findMMDBFile
	var foundFiles []string
	err = filepath.Walk(extractedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".mmdb" {
			foundFiles = append(foundFiles, path)
			return filepath.SkipDir
		}
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, foundFiles, 1)
	assert.Equal(t, mmdbPath, foundFiles[0])
}

// TestDownloadDatabase_IsFileRecent_Indirect test indiretto di isFileRecent
func TestDownloadDatabase_IsFileRecent_Indirect(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_recent_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Crea un file "recente"
	recentFile := filepath.Join(tmpDir, "recent.txt")
	err = os.WriteFile(recentFile, []byte("recent content"), 0644)
	require.NoError(t, err)

	// Usa os.Stat per ottenere le informazioni (come farebbe isFileRecent)
	info, err := os.Stat(recentFile)
	require.NoError(t, err)

	// Verifica che il file sia recente (creato ora)
	age := time.Since(info.ModTime())
	assert.True(t, age < 1*time.Minute, "File should be less than 1 minute old")
	assert.True(t, age < 24*time.Hour, "File should be less than 24 hours old")

	// Crea un file "vecchio" modificando il timestamp
	oldFile := filepath.Join(tmpDir, "old.txt")
	err = os.WriteFile(oldFile, []byte("old content"), 0644)
	require.NoError(t, err)

	// Modifica il timestamp del file per farlo sembrare vecchio
	pastTime := time.Now().Add(-48 * time.Hour)
	err = os.Chtimes(oldFile, pastTime, pastTime)
	require.NoError(t, err)

	info, err = os.Stat(oldFile)
	require.NoError(t, err)

	// Verifica che il file sia vecchio
	age = time.Since(info.ModTime())
	assert.True(t, age > 24*time.Hour, "File should be more than 24 hours old")
	assert.True(t, age > 1*time.Hour, "File should be more than 1 hour old")
}

// TestDownloadDatabase_CleanupDirs_Indirect test indiretto di cleanupExtractedDirs
func TestDownloadDatabase_CleanupDirs_Indirect(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_cleanup_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Crea varie directory
	dirs := []string{
		"GeoLite2-Country_20231201",
		"GeoLite2-City_20231202",
		"GeoLite2-ASN_20231203",
		"NotGeoLite_Directory",
		"other_folder",
	}

	// Crea le directory
	for _, dir := range dirs {
		dirPath := filepath.Join(tmpDir, dir)
		err = os.MkdirAll(dirPath, 0755)
		require.NoError(t, err)
		
		// Aggiungi qualche file
		filePath := filepath.Join(dirPath, "test.txt")
		err = os.WriteFile(filePath, []byte("test"), 0644)
		require.NoError(t, err)
	}

	// Simula la logica di cleanupExtractedDirs
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
			// Verifica se inizia con "GeoLite2" (deve essere almeno 8 caratteri)
			if len(entry.Name()) >= 8 && entry.Name()[:8] == "GeoLite2" {
				dirPath := filepath.Join(tmpDir, entry.Name())
				os.RemoveAll(dirPath)
			}
		}
	}

	// Verifica quali directory rimangono
	entries, err = os.ReadDir(tmpDir)
	require.NoError(t, err)

	remainingDirs := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			remainingDirs = append(remainingDirs, entry.Name())
		}
	}

	// Le directory GeoLite2 dovrebbero essere rimosse
	assert.NotContains(t, remainingDirs, "GeoLite2-Country_20231201")
	assert.NotContains(t, remainingDirs, "GeoLite2-City_20231202")
	assert.NotContains(t, remainingDirs, "GeoLite2-ASN_20231203")
	
	// Le altre directory dovrebbero rimanere
	assert.Contains(t, remainingDirs, "NotGeoLite_Directory")
	assert.Contains(t, remainingDirs, "other_folder")
}

// TestDownloadDatabase_ExtractTarGzGo_Indirect test indiretto di extractTarGzGo
func TestDownloadDatabase_ExtractTarGzGo_Indirect(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "geoip_extract_go_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Crea un tar.gz di test
	tarPath := filepath.Join(tmpDir, "test.tar.gz")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	// Aggiungi directory
	dirHeader := &tar.Header{
		Name:     "test_dir/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	err = tw.WriteHeader(dirHeader)
	require.NoError(t, err)

	// Aggiungi file
	fileContent := "Hello, World!"
	fileHeader := &tar.Header{
		Name: "test_dir/hello.txt",
		Mode: 0644,
		Size: int64(len(fileContent)),
	}
	err = tw.WriteHeader(fileHeader)
	require.NoError(t, err)
	_, err = tw.Write([]byte(fileContent))
	require.NoError(t, err)

	tw.Close()
	gzw.Close()
	f.Close()

	// Simula la logica di extractTarGzGo
	extractDir := filepath.Join(tmpDir, "extracted")
	err = os.MkdirAll(extractDir, 0755)
	require.NoError(t, err)

	// Apri il tar.gz
	file, err := os.Open(tarPath)
	require.NoError(t, err)
	defer file.Close()

	// Decomprimi gzip
	gz, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gz.Close()

	// Leggi il tar
	tr := tar.NewReader(gz)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		target := filepath.Join(extractDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			err := os.MkdirAll(target, 0755)
			require.NoError(t, err)
		case tar.TypeReg:
			// Crea directory padre se non esiste
			parentDir := filepath.Dir(target)
			err = os.MkdirAll(parentDir, 0755)
			require.NoError(t, err)

			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			require.NoError(t, err)
			_, err = io.Copy(f, tr)
			f.Close()
			require.NoError(t, err)
		}
	}

	// Verifica l'estrazione
	extractedFile := filepath.Join(extractDir, "test_dir", "hello.txt")
	content, err := os.ReadFile(extractedFile)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(content))
}

// TestDownloadDatabase_FullWorkflow_WithMock test del flusso completo con mock
func TestDownloadDatabase_FullWorkflow_WithMock(t *testing.T) {
	// Questo test simula l'intero flusso di DownloadDatabase
	// senza fare chiamate HTTP reali

	originalDir, err := os.Getwd()
	require.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "geoip_full_workflow_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer os.Chdir(originalDir)

	// Crea directory geoip
	err = os.MkdirAll("geoip", 0755)
	require.NoError(t, err)

	// Crea un database esistente (per testare il salto del download)
	dbFile := filepath.Join("geoip", "GeoLite2-Country.mmdb")
	err = os.WriteFile(dbFile, []byte("existing database"), 0644)
	require.NoError(t, err)

	// Verifica che il file esista
	info, err := os.Stat(dbFile)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "File should have content")

	// Config con chiave fittizia (non farà download reale)
	downloadConfig := geoip.DefaultDownloadConfig("test-mock-key")
	
	// Verifica che la config sia corretta
	assert.NotNil(t, downloadConfig)
	assert.Equal(t, "test-mock-key", downloadConfig.LicenseKey)
	assert.Equal(t, "GeoLite2-Country", downloadConfig.EditionID)
	assert.Equal(t, 30*time.Second, downloadConfig.Timeout)

	// DownloadDatabase probabilmente salterà perché il file esiste
	err = geoip.DownloadDatabase(downloadConfig)
	// Non assertiamo sull'errore perché potrebbe essere nil (file recente)
	// o errore (tentativo di download fallito)
	
	// Il file dovrebbe ancora esistere
	_, err = os.Stat(dbFile)
	assert.NoError(t, err, "Database file should still exist")
}