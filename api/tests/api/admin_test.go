package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindAll(ctx context.Context) ([]models.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) FindPaginated(ctx context.Context, offset, limit int) ([]models.User, int64, error) {
	args := m.Called(ctx, offset, limit)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uint) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) FindByRole(ctx context.Context, role string) ([]models.User, error) {
	args := m.Called(ctx, role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) CountByRole(ctx context.Context, role string) (int64, error) {
	args := m.Called(ctx, role)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateRole(ctx context.Context, id uint, role string) error {
	args := m.Called(ctx, id, role)
	return args.Error(0)
}

func (m *MockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

// TestNewGetUsersHandler_Success tests successful user listing with pagination
func TestNewGetUsersHandler_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	users := []models.User{
		{
			ID:           1,
			Email:        "admin@example.com",
			Name:         "Admin User",
			Role:         "admin",
			Active:       true,
			TwoFAEnabled: true,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
		{
			ID:           2,
			Email:        "user@example.com",
			Name:         "Test User",
			Role:         "user",
			Active:       true,
			TwoFAEnabled: false,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return(users, int64(2), nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.NotNil(t, response["users"])
	assert.NotNil(t, response["pagination"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetUsersHandler_WithCustomLimit tests user listing with custom limit
func TestNewGetUsersHandler_WithCustomLimit(t *testing.T) {
	mockRepo := new(MockUserRepository)
	users := []models.User{
		{
			ID:        1,
			Email:     "admin@example.com",
			Name:      "Admin User",
			Role:      "admin",
			Active:    true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 0, 50).Return(users, int64(1), nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users?limit=50&offset=0", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetUsersHandler_WithOffset tests user listing with offset pagination
func TestNewGetUsersHandler_WithOffset(t *testing.T) {
	mockRepo := new(MockUserRepository)
	users := []models.User{
		{
			ID:        3,
			Email:     "user3@example.com",
			Name:      "User 3",
			Role:      "user",
			Active:    true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 20, 20).Return(users, int64(100), nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users?limit=20&offset=20", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetUsersHandler_InvalidLimit tests handling of invalid limit parameter
func TestNewGetUsersHandler_InvalidLimit(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users?limit=invalid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewGetUsersHandler_InvalidOffset tests handling of invalid offset parameter
func TestNewGetUsersHandler_InvalidOffset(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users?offset=invalid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewGetUsersHandler_ServiceError tests handling of service errors
func TestNewGetUsersHandler_ServiceError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return(nil, int64(0), fmt.Errorf("database error"))

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestGetUsers tests the deprecated GetUsers stub function
func TestGetUsers(t *testing.T) {
	router := gin.New()
	router.GET("/admin/users", internalapi.GetUsers)

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "use NewGetUsersHandler", response["error"])
}

// TestNewUpdateUserHandler_Success tests successful user update
func TestNewUpdateUserHandler_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:           2,
		Email:        "user@example.com",
		Name:         "Test User",
		Role:         "user",
		Active:       true,
		TwoFAEnabled: false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 2 && u.Name == "Updated User"
	})).Return(nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1)) // Different from target user
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name":   "Updated User",
		"role":   "admin",
		"active": true,
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "User updated successfully", response["message"])

	mockRepo.AssertExpectations(t)
}

// TestNewUpdateUserHandler_InvalidUserID tests handling of invalid user ID format
func TestNewUpdateUserHandler_InvalidUserID(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	req, _ := http.NewRequest("PUT", "/admin/users/invalid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewUpdateUserHandler_NoAuthContext tests handling when user_id is not in context
func TestNewUpdateUserHandler_NoAuthContext(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	// No user_id in context
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name": "Updated User",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNewUpdateUserHandler_InvalidUserIDType tests handling of invalid user_id type in context
func TestNewUpdateUserHandler_InvalidUserIDType(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "invalid_string") // Wrong type
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name": "Updated User",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNewUpdateUserHandler_CannotEditOwnAccount tests prevention of self-editing
func TestNewUpdateUserHandler_CannotEditOwnAccount(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(2)) // Same as target user
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name": "Updated User",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestNewUpdateUserHandler_InvalidJSON tests handling of invalid JSON in request
func TestNewUpdateUserHandler_InvalidJSON(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewUpdateUserHandler_UserNotFound tests handling when user is not found
func TestNewUpdateUserHandler_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockRepo.On("FindByID", mock.Anything, uint(999)).Return(nil, fmt.Errorf("not found"))

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name": "Updated User",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/999", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewUpdateUserHandler_UpdateError tests handling of update service error
func TestNewUpdateUserHandler_UpdateError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:    2,
		Email: "user@example.com",
		Name:  "Test User",
		Role:  "user",
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Update", mock.Anything, mock.Anything).Return(fmt.Errorf("update failed"))

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name": "Updated User",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewUpdateUserHandler_UpdateOnlyName tests updating only name field
func TestNewUpdateUserHandler_UpdateOnlyName(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:       2,
		Email:    "user@example.com",
		Name:     "Test User",
		Role:     "user",
		Active:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Name == "New Name" && u.Role == "user" // Role should not change
	})).Return(nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"name": "New Name",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewUpdateUserHandler_UpdateOnlyRole tests updating only role field
func TestNewUpdateUserHandler_UpdateOnlyRole(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:       2,
		Email:    "user@example.com",
		Name:     "Test User",
		Role:     "user",
		Active:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Role == "admin" && u.Name == "Test User" // Name should not change
	})).Return(nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	updateReq := map[string]interface{}{
		"role": "admin",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewUpdateUserHandler_UpdateOnlyActive tests updating only active flag
func TestNewUpdateUserHandler_UpdateOnlyActive(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:       2,
		Email:    "user@example.com",
		Name:     "Test User",
		Role:     "user",
		Active:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Active == false && u.Name == "Test User"
	})).Return(nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	activeFlag := false
	updateReq := map[string]interface{}{
		"active": &activeFlag,
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewDeleteUserHandler_Success tests successful user deletion
func TestNewDeleteUserHandler_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:    2,
		Email: "user@example.com",
		Name:  "Test User",
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Delete", mock.Anything, uint(2)).Return(nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Contains(t, response["message"], "deleted successfully")

	mockRepo.AssertExpectations(t)
}

// TestNewDeleteUserHandler_InvalidUserID tests handling of invalid user ID format
func TestNewDeleteUserHandler_InvalidUserID(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/invalid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewDeleteUserHandler_NoAuthContext tests handling when user_id is not in context
func TestNewDeleteUserHandler_NoAuthContext(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	// No user_id in context
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNewDeleteUserHandler_InvalidUserIDType tests handling of invalid user_id type in context
func TestNewDeleteUserHandler_InvalidUserIDType(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "invalid_string") // Wrong type
	})
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNewDeleteUserHandler_CannotDeleteOwnAccount tests prevention of self-deletion
func TestNewDeleteUserHandler_CannotDeleteOwnAccount(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(2)) // Same as target user
	})
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestNewDeleteUserHandler_UserNotFound tests handling when user is not found
func TestNewDeleteUserHandler_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockRepo.On("FindByID", mock.Anything, uint(999)).Return(nil, fmt.Errorf("not found"))

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/999", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewDeleteUserHandler_DeleteError tests handling of delete service error
func TestNewDeleteUserHandler_DeleteError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:    2,
		Email: "user@example.com",
		Name:  "Test User",
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Delete", mock.Anything, uint(2)).Return(fmt.Errorf("delete failed"))

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewDeleteUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.DELETE("/admin/users/:id", handler)

	req, _ := http.NewRequest("DELETE", "/admin/users/2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetUsersHandler_EmptyList tests handling of empty user list
func TestNewGetUsersHandler_EmptyList(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return([]models.User{}, int64(0), nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotNil(t, response["users"])
	assert.NotNil(t, response["pagination"])

	mockRepo.AssertExpectations(t)
}

// TestNewUpdateUserHandler_EmptyUpdate tests updating with empty request body fields
func TestNewUpdateUserHandler_EmptyUpdate(t *testing.T) {
	mockRepo := new(MockUserRepository)
	user := &models.User{
		ID:       2,
		Email:    "user@example.com",
		Name:     "Test User",
		Role:     "user",
		Active:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockRepo.On("FindByID", mock.Anything, uint(2)).Return(user, nil)
	mockRepo.On("Update", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Name == "Test User" && u.Role == "user"
	})).Return(nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewUpdateUserHandler(userService)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
	})
	router.PUT("/admin/users/:id", handler)

	// Request with empty/zero values - should not update
	updateReq := map[string]interface{}{
		"name": "",
		"role": "",
	}
	body, _ := json.Marshal(updateReq)

	req, _ := http.NewRequest("PUT", "/admin/users/2", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetUsersHandler_SanitizedResponse tests that sensitive fields are hidden
func TestNewGetUsersHandler_SanitizedResponse(t *testing.T) {
	mockRepo := new(MockUserRepository)
	users := []models.User{
		{
			ID:             1,
			Email:          "admin@example.com",
			Name:           "Admin User",
			Role:           "admin",
			PasswordHash:   "hashedpassword", // Should not be in response
			Active:         true,
			TwoFAEnabled:   true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return(users, int64(1), nil)

	userService := service.NewUserService(mockRepo)
	handler := internalapi.NewGetUsersHandler(userService)

	router := gin.New()
	router.GET("/admin/users", handler)

	req, _ := http.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Verify response structure
	users_data := response["users"].([]interface{})
	if len(users_data) > 0 {
		user_obj := users_data[0].(map[string]interface{})
		// Check that sensitive fields are NOT in response
		assert.Nil(t, user_obj["password_hash"])
		// Check that safe fields ARE in response
		assert.NotNil(t, user_obj["email"])
		assert.NotNil(t, user_obj["name"])
		assert.NotNil(t, user_obj["role"])
	}

	mockRepo.AssertExpectations(t)
}
