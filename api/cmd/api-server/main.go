package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/gin-gonic/gin"
	"github.com/swaggo/gin-swagger"
	"github.com/swaggo/files"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/config"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/middleware"
	_ "github.com/PiCas19/waf-siem-advanced-detection/api/docs"
)

func main() {
	// Carica variabili d'ambiente dal file .env
	if err := godotenv.Load(); err == nil {
		fmt.Println("✓ Loaded environment variables from .env")
	} else {
		fmt.Println("ℹ No .env file found, using environment variables")
	}

	// Carica configurazione centralizzata
	cfg := config.LoadFromEnv()

	// Inizializza logger strutturato
	if err := logger.InitLogger(cfg.Logger.Level, cfg.Logger.OutputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := logger.CloseLogger(); err != nil {
			logger.WithError(err).Error("Failed to close logger")
		}
	}()

	logger.Log.WithFields(map[string]interface{}{
		"log_level": cfg.Logger.Level,
		"output":    cfg.Logger.OutputPath,
	}).Info("Logger initialized")

	// Imposta Gin mode
	if cfg.Logger.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Inizializza database
	logger.Log.Info("Initializing database...")
	db, err := database.Initialize(cfg.Database.Path)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}
	logger.Log.WithFields(map[string]interface{}{
		"database": cfg.Database.Path,
	}).Info("Database initialized")

	// Seed default users
	if err := database.SeedDefaultUsers(db); err != nil {
		logger.WithError(err).Warn("Failed to seed default users")
	}

	// Inizializza MaxMind GeoIP
	logger.Log.Info("Initializing GeoIP database...")
	licenseKey := os.Getenv("MAXMIND_LICENSE_KEY")
	if licenseKey != "" {
		geoConfig := geoip.DefaultDownloadConfig(licenseKey)
		if err := geoip.DownloadDatabase(geoConfig); err != nil {
			logger.WithError(err).Warn("Failed to download MaxMind database, using fallback")
		} else {
			logger.Log.Info("MaxMind GeoIP database ready")
		}
	} else {
		logger.Log.Warn("MAXMIND_LICENSE_KEY not set, using fallback IP ranges")
	}

	// Crea Gin router con configurazione esplicita
	engine := gin.New()

	// Imposta trusted proxies
	engine.SetTrustedProxies([]string{"127.0.0.1", "::1", "192.168.216.0/24", "172.16.216.0/24"})

	// Aggiungi middleware
	engine.Use(gin.Logger())
	engine.Use(gin.Recovery())

	// Middleware personalizzati
	engine.Use(middleware.RequestIDMiddleware())
	engine.Use(middleware.ContextPropagationMiddleware())

	// CORS middleware (extracted to middleware/cors.go for reusability)
	engine.Use(middleware.CORSMiddleware(&cfg.CORS))

	// Aggiungi rate limiting se abilitato
	var rateLimiter *middleware.RateLimiter
	if cfg.RateLimit.Enabled {
		rateLimiter = middleware.NewRateLimiter(float64(cfg.RateLimit.RPS), cfg.RateLimit.BurstSize)
		engine.Use(middleware.RateLimitMiddleware(rateLimiter))
		logger.Log.Info("Rate limiting enabled")
	}

	// Health check endpoint
	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now(),
		})
	})

	// Readiness probe
	engine.GET("/health/ready", func(c *gin.Context) {
		// Puoi aggiungere controlli più sofisticati qui
		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
			"time":   time.Now(),
		})
	})

	// Liveness probe
	engine.GET("/health/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "alive",
			"time":   time.Now(),
		})
	})

	// Setup routes
	api.SetupRoutes(engine, db)

	// Setup Swagger documentation
	engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	logger.Log.Info("Swagger documentation available at /swagger/index.html")

	// Inizializza threat intelligence service
	api.InitTIService(db)

	// Inizializza stats handler
	api.SetStatsDB(db)

	// Crea server HTTP
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:           addr,
		Handler:        engine,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Avvia server in goroutine
	go func() {
		logger.Log.WithFields(map[string]interface{}{
			"address": addr,
		}).Info("Starting API server")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Server failed to start")
		}
	}()

	// Gestisci graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	logger.Log.Info("Shutdown signal received, gracefully shutting down...")

	// Context con timeout per graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Chiudi server
	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	// Chiudi database
	sqlDB, err := db.DB()
	if err == nil {
		if err := sqlDB.Close(); err != nil {
			logger.WithError(err).Error("Failed to close database")
		}
	}

	logger.Log.Info("Server stopped gracefully")
}