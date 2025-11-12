package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestNewGetUsersHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Seed test users
	users := []models.User{
		{
			Email:        "user1@example.com",
			Name:         "User One",
			Role:         "admin",
			Active:       true,
			TwoFAEnabled: false,
		},
		{
			Email:        "user2@example.com",
			Name:         "User Two",
			Role:         "user",
			Active:       true,
			TwoFAEnabled: true,
		},
	}

	for _, user := range users {
		assert.NoError(t, db.Create(&user).Error)
	}

	router := gin.New()
	router.GET("/users", api.NewGetUsersHandler(db))

	t.Run("get users success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Users []map[string]interface{} `json:"users"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 2, len(response.Users))

		// Verify password is not included
		for _, user := range response.Users {
			assert.NotContains(t, user, "password")
		}
	})

	t.Run("get users returns correct fields", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Users []map[string]interface{} `json:"users"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		user := response.Users[0]
		assert.Contains(t, user, "id")
		assert.Contains(t, user, "email")
		assert.Contains(t, user, "name")
		assert.Contains(t, user, "role")
		assert.Contains(t, user, "active")
		assert.Contains(t, user, "two_fa_enabled")
		assert.Contains(t, user, "created_at")
		assert.Contains(t, user, "updated_at")
	})
}

func TestNewUpdateUserHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Create test users
	authUser := models.User{
		Email:  "admin@example.com",
		Name:   "Admin",
		Role:   "admin",
		Active: true,
	}
	targetUser := models.User{
		Email:  "user@example.com",
		Name:   "User",
		Role:   "user",
		Active: true,
	}

	assert.NoError(t, db.Create(&authUser).Error)
	assert.NoError(t, db.Create(&targetUser).Error)

	t.Run("update user success", func(t *testing.T) {
		payload := gin.H{
			"name": "Updated Name",
			"role": "admin",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("user_id", authUser.ID)
		c.Set("user_email", authUser.Email)
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", targetUser.ID)}}
		c.Request = httptest.NewRequest("PUT", "/users/"+fmt.Sprintf("%d", targetUser.ID), bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")

		handler := api.NewUpdateUserHandler(db)
		handler(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var updatedUser models.User
		db.First(&updatedUser, targetUser.ID)
		assert.Equal(t, "Updated Name", updatedUser.Name)
	})

	t.Run("update user not found", func(t *testing.T) {
		payload := gin.H{
			"name": "Updated Name",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("user_id", authUser.ID)
		c.Set("user_email", authUser.Email)
		c.Params = []gin.Param{{Key: "id", Value: "999"}}
		c.Request = httptest.NewRequest("PUT", "/users/999", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")

		handler := api.NewUpdateUserHandler(db)
		handler(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("update own account forbidden", func(t *testing.T) {
		payload := gin.H{
			"name": "Updated Name",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("user_id", authUser.ID)
		c.Set("user_email", authUser.Email)
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", authUser.ID)}}
		c.Request = httptest.NewRequest("PUT", "/users/"+fmt.Sprintf("%d", authUser.ID), bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")

		handler := api.NewUpdateUserHandler(db)
		handler(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestNewDeleteUserHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Create test users
	authUser := models.User{
		Email:  "admin@example.com",
		Name:   "Admin",
		Role:   "admin",
		Active: true,
	}
	targetUser := models.User{
		Email:  "user@example.com",
		Name:   "User",
		Role:   "user",
		Active: true,
	}

	assert.NoError(t, db.Create(&authUser).Error)
	assert.NoError(t, db.Create(&targetUser).Error)

	t.Run("delete user success", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("user_id", authUser.ID)
		c.Set("user_email", authUser.Email)
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", targetUser.ID)}}
		c.Request = httptest.NewRequest("DELETE", "/users/"+fmt.Sprintf("%d", targetUser.ID), nil)

		handler := api.NewDeleteUserHandler(db)
		handler(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var deletedUser models.User
		result := db.First(&deletedUser, targetUser.ID)
		assert.Equal(t, gorm.ErrRecordNotFound, result.Error)
	})

	t.Run("delete own account forbidden", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("user_id", authUser.ID)
		c.Set("user_email", authUser.Email)
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", authUser.ID)}}
		c.Request = httptest.NewRequest("DELETE", "/users/"+fmt.Sprintf("%d", authUser.ID), nil)

		handler := api.NewDeleteUserHandler(db)
		handler(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("delete user not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("user_id", authUser.ID)
		c.Set("user_email", authUser.Email)
		c.Params = []gin.Param{{Key: "id", Value: "999"}}
		c.Request = httptest.NewRequest("DELETE", "/users/999", nil)

		handler := api.NewDeleteUserHandler(db)
		handler(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestGetUsers(t *testing.T) {
	t.Run("deprecated get users", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		api.GetUsers(c)

		assert.Equal(t, 400, w.Code)
		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewGetUsersHandler", response["error"])
	})
}
