// tests/service/user_service_test.go
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestNewUserService(t *testing.T) {
	mockRepo := &MockUserRepository{}
	svc := service.NewUserService(mockRepo)
	
	assert.NotNil(t, svc)
}

func TestUserService_GetAllUsers(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expected := []models.User{
			{ID: 1, Email: "admin@example.com", Name: "Admin", Role: "admin", Active: true},
			{ID: 2, Email: "user@example.com", Name: "User", Role: "user", Active: true},
		}
		
		mockRepo.On("FindAll", ctx).Return(expected, nil)
		
		result, err := svc.GetAllUsers(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindAll", ctx).Return([]models.User{}, expectedErr)
		
		result, err := svc.GetAllUsers(ctx)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NoUsers", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindAll", ctx).Return([]models.User{}, nil)
		
		result, err := svc.GetAllUsers(ctx)
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_GetUsersPaginated(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expected := []models.User{
			{ID: 1, Email: "admin@example.com", Name: "Admin", Role: "admin"},
			{ID: 2, Email: "user1@example.com", Name: "User 1", Role: "user"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetUsersPaginated(ctx, 0, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.User{}, int64(0), expectedErr)
		
		result, total, err := svc.GetUsersPaginated(ctx, 0, 10)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_GetUserByID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expected := &models.User{
			ID:    1,
			Email: "admin@example.com",
			Name:  "Admin",
			Role:  "admin",
			Active: true,
		}
		
		mockRepo.On("FindByID", ctx, uint(1)).Return(expected, nil)
		
		result, err := svc.GetUserByID(ctx, 1)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetUserByID(ctx, 0)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "user ID must be set")
		mockRepo.AssertNotCalled(t, "FindByID")
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.User)(nil), nil)
		
		result, err := svc.GetUserByID(ctx, 1)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "user not found")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.User)(nil), expectedErr)
		
		result, err := svc.GetUserByID(ctx, 1)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to get user")
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_GetUserByEmail(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expected := &models.User{
			ID:    1,
			Email: "admin@example.com",
			Name:  "Admin",
			Role:  "admin",
		}
		
		mockRepo.On("FindByEmail", ctx, "admin@example.com").Return(expected, nil)
		
		result, err := svc.GetUserByEmail(ctx, "admin@example.com")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyEmail", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetUserByEmail(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "email cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByEmail")
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByEmail", ctx, "nonexistent@example.com").Return((*models.User)(nil), nil)
		
		result, err := svc.GetUserByEmail(ctx, "nonexistent@example.com")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "user not found")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByEmail", ctx, "admin@example.com").Return((*models.User)(nil), expectedErr)
		
		result, err := svc.GetUserByEmail(ctx, "admin@example.com")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to get user")
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_GetUsersByRole(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expected := []models.User{
			{ID: 1, Email: "admin1@example.com", Name: "Admin 1", Role: "admin"},
			{ID: 2, Email: "admin2@example.com", Name: "Admin 2", Role: "admin"},
		}
		
		mockRepo.On("FindByRole", ctx, "admin").Return(expected, nil)
		
		result, err := svc.GetUsersByRole(ctx, "admin")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyRole", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetUsersByRole(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "role cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByRole")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByRole", ctx, "user").Return([]models.User{}, expectedErr)
		
		result, err := svc.GetUsersByRole(ctx, "user")
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NoUsersWithRole", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByRole", ctx, "operator").Return([]models.User{}, nil)
		
		result, err := svc.GetUsersByRole(ctx, "operator")
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_GetUsersCount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 25
		mockRepo.On("Count", ctx).Return(expectedCount, nil)
		
		count, err := svc.GetUsersCount(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Count", ctx).Return(int64(0), expectedErr)
		
		count, err := svc.GetUsersCount(ctx)
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_GetUserCountByRole(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 5
		mockRepo.On("CountByRole", ctx, "admin").Return(expectedCount, nil)
		
		count, err := svc.GetUserCountByRole(ctx, "admin")
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyRole", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		count, err := svc.GetUserCountByRole(ctx, "")
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Contains(t, err.Error(), "role cannot be empty")
		mockRepo.AssertNotCalled(t, "CountByRole")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("CountByRole", ctx, "user").Return(int64(0), expectedErr)
		
		count, err := svc.GetUserCountByRole(ctx, "user")
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_CreateUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			Email:        "newuser@example.com",
			PasswordHash: "hashed_password",
			Name:         "New User",
			Role:         "user",
			Active:       true,
		}
		
		mockRepo.On("ExistsByEmail", ctx, "newuser@example.com").Return(false, nil)
		mockRepo.On("Create", ctx, user).Return(nil)
		
		err := svc.CreateUser(ctx, user)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilUser", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		err := svc.CreateUser(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user cannot be nil")
		mockRepo.AssertNotCalled(t, "ExistsByEmail")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("EmptyEmail", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			PasswordHash: "hashed_password",
			Name:         "User",
		}
		
		err := svc.CreateUser(ctx, user)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email cannot be empty")
		mockRepo.AssertNotCalled(t, "ExistsByEmail")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("EmailAlreadyExists", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			Email:        "existing@example.com",
			PasswordHash: "hashed_password",
			Name:         "User",
		}
		
		mockRepo.On("ExistsByEmail", ctx, "existing@example.com").Return(true, nil)
		
		err := svc.CreateUser(ctx, user)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user with email existing@example.com already exists")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("ExistsByEmailError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			Email:        "test@example.com",
			PasswordHash: "hashed_password",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("ExistsByEmail", ctx, "test@example.com").Return(false, expectedErr)
		
		err := svc.CreateUser(ctx, user)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to check user existence")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			Email:        "new@example.com",
			PasswordHash: "hashed_password",
			Name:         "New User",
		}
		
		mockRepo.On("ExistsByEmail", ctx, "new@example.com").Return(false, nil)
		expectedErr := errors.New("database error")
		mockRepo.On("Create", ctx, user).Return(expectedErr)
		
		err := svc.CreateUser(ctx, user)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("UserWithAllFields", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			ID:                   1,
			Email:               "fulluser@example.com",
			PasswordHash:        "bcrypt_hashed_password",
			Name:                "Full User",
			Role:                "admin",
			Active:              true,
			TwoFAEnabled:        true,
			MustSetup2FA:        false,
			OTPSecret:           "JBSWY3DPEHPK3PXP",
			BackupCodes:         `["code1","code2","code3"]`,
			PasswordResetToken:  "reset_token",
		}
		
		mockRepo.On("ExistsByEmail", ctx, "fulluser@example.com").Return(false, nil)
		mockRepo.On("Create", ctx, user).Return(nil)
		
		err := svc.CreateUser(ctx, user)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_UpdateUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			ID:    1,
			Email: "updated@example.com",
			Name:  "Updated User",
			Role:  "admin",
			Active: true,
		}
		
		mockRepo.On("Update", ctx, user).Return(nil)
		
		err := svc.UpdateUser(ctx, user)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilUser", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateUser(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user cannot be nil")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			Email: "test@example.com",
			Name:  "User",
		}
		
		err := svc.UpdateUser(ctx, user)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user ID must be set")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			ID:    1,
			Email: "test@example.com",
			Name:  "Updated Name",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Update", ctx, user).Return(expectedErr)
		
		err := svc.UpdateUser(ctx, user)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("PartialUpdate", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		user := &models.User{
			ID:    1,
			Active: false, // Solo aggiornamento dello stato
		}
		
		mockRepo.On("Update", ctx, user).Return(nil)
		
		err := svc.UpdateUser(ctx, user)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_DeleteUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("Delete", ctx, uint(1)).Return(nil)
		
		err := svc.DeleteUser(ctx, 1)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		err := svc.DeleteUser(ctx, 0)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user ID must be set")
		mockRepo.AssertNotCalled(t, "Delete")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Delete", ctx, uint(1)).Return(expectedErr)
		
		err := svc.DeleteUser(ctx, 1)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_UpdateUserRole(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("UpdateRole", ctx, uint(1), "admin").Return(nil)
		
		err := svc.UpdateUserRole(ctx, 1, "admin")
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateUserRole(ctx, 0, "admin")
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user ID must be set")
		mockRepo.AssertNotCalled(t, "UpdateRole")
	})
	
	t.Run("EmptyRole", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateUserRole(ctx, 1, "")
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateRole")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("UpdateRole", ctx, uint(1), "user").Return(expectedErr)
		
		err := svc.UpdateUserRole(ctx, 1, "user")
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestUserService_CheckEmailExists(t *testing.T) {
	t.Run("Success_Exists", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("ExistsByEmail", ctx, "existing@example.com").Return(true, nil)
		
		exists, err := svc.CheckEmailExists(ctx, "existing@example.com")
		
		assert.NoError(t, err)
		assert.True(t, exists)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("Success_NotExists", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("ExistsByEmail", ctx, "new@example.com").Return(false, nil)
		
		exists, err := svc.CheckEmailExists(ctx, "new@example.com")
		
		assert.NoError(t, err)
		assert.False(t, exists)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyEmail", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		exists, err := svc.CheckEmailExists(ctx, "")
		
		assert.Error(t, err)
		assert.False(t, exists)
		assert.Contains(t, err.Error(), "email cannot be empty")
		mockRepo.AssertNotCalled(t, "ExistsByEmail")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockUserRepository{}
		svc := service.NewUserService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("ExistsByEmail", ctx, "test@example.com").Return(false, expectedErr)
		
		exists, err := svc.CheckEmailExists(ctx, "test@example.com")
		
		assert.Error(t, err)
		assert.False(t, exists)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}