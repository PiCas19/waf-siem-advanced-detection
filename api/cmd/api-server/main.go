package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
)

func main() {
	// Try to load variables from a local .env file for development.
	// This is non-fatal: if the file doesn't exist we continue reading from the environment.
	if err := godotenv.Load(); err == nil {
		log.Println("Loaded environment variables from .env")
	} else {
		log.Println("No .env file found or failed to load; using environment variables")
	}

    // Resolve configuration from env with sensible defaults
    dbPath := os.Getenv("DATABASE_URL")
    if dbPath == "" {
        dbPath = "./data/waf.db"
    }
    port := os.Getenv("PORT")
    if port == "" {
        port = "8081"
    }

    // Initialize database
    db, err := database.Initialize(dbPath)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Seed default users (creates root admin if it doesn't exist)
	if err := database.SeedDefaultUsers(db); err != nil {
		log.Printf("[WARN] Failed to seed default users: %v\n", err)
	}

	// Initialize MaxMind GeoIP database
	licenseKey := os.Getenv("MAXMIND_LICENSE_KEY")
	if licenseKey != "" {
		log.Println("[INFO] MaxMind license key found, attempting to download/update database...")
		config := geoip.DefaultDownloadConfig(licenseKey)
		if err := geoip.DownloadDatabase(config); err != nil {
			log.Printf("[WARN] Failed to download MaxMind database: %v. Will use fallback IP ranges.\n", err)
		}
	} else {
		log.Println("[WARN] MAXMIND_LICENSE_KEY not set. Using fallback IP ranges. To use MaxMind, set MAXMIND_LICENSE_KEY environment variable.")
	}

	// Create Gin router
	r := gin.Default()

	// Set explicit trusted proxies (disable "trust all" warning)
	// Configure trusted proxies based on your network architecture:
	// - 127.0.0.1, ::1: localhost (always safe)
	// - 192.168.216.0/24: Your internal LAN
	// - 172.16.216.0/24: Your DMZ
	r.SetTrustedProxies([]string{"127.0.0.1", "::1", "192.168.216.0/24", "172.16.216.0/24"})

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})
	
	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	
	// Setup routes
	api.SetupRoutes(r, db)

	// Initialize threat intelligence service with database for blocklist checking
	api.InitTIService(db)

	// Initialize stats handler with database
	api.SetStatsDB(db)

    // Start server
    addr := fmt.Sprintf(":%s", port)
    log.Printf("Starting API server on %s (DB: %s)\n", addr, dbPath)
    if err := r.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}