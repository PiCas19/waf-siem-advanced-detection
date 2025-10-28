package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
)

func main() {
	// Initialize database
	db, err := database.Initialize("./data/waf.db")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
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

	// Initialize stats handler with database
	api.SetStatsDB(db)

	// Start server
	log.Println("Starting API server on :8081")
	if err := r.Run(":8081"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}