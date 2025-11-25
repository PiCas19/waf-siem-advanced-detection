package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// UserService handles business logic for user management, providing methods to create,
// update, delete, and query dashboard users with role-based access control.
//
// Fields:
//   - userRepo (repository.UserRepository): Repository for user database operations
//
// Example Usage:
//   userService := service.NewUserService(userRepo)
//   user, err := userService.GetUserByEmail(ctx, "admin@example.com")
//
// Thread Safety: Thread-safe when using appropriate database transaction handling.
//
// See Also: User, UserRepository
type UserService struct {
	userRepo repository.UserRepository
}

// NewUserService creates a new user service
func NewUserService(userRepo repository.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

// GetAllUsers retrieves all users
func (s *UserService) GetAllUsers(ctx context.Context) ([]models.User, error) {
	return s.userRepo.FindAll(ctx)
}

// GetUsersPaginated retrieves paginated users with total count
func (s *UserService) GetUsersPaginated(ctx context.Context, offset, limit int) ([]models.User, int64, error) {
	return s.userRepo.FindPaginated(ctx, offset, limit)
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(ctx context.Context, id uint) (*models.User, error) {
	if id == 0 {
		return nil, fmt.Errorf("user ID must be set")
	}
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// GetUsersByRole retrieves all users with a specific role
func (s *UserService) GetUsersByRole(ctx context.Context, role string) ([]models.User, error) {
	if role == "" {
		return nil, fmt.Errorf("role cannot be empty")
	}
	return s.userRepo.FindByRole(ctx, role)
}

// GetUsersCount returns total number of users
func (s *UserService) GetUsersCount(ctx context.Context) (int64, error) {
	return s.userRepo.Count(ctx)
}

// GetUserCountByRole returns count of users with a specific role
func (s *UserService) GetUserCountByRole(ctx context.Context, role string) (int64, error) {
	if role == "" {
		return 0, fmt.Errorf("role cannot be empty")
	}
	return s.userRepo.CountByRole(ctx, role)
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, user *models.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	if user.Email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(ctx, user.Email)
	if err != nil {
		return fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists {
		return fmt.Errorf("user with email %s already exists", user.Email)
	}

	return s.userRepo.Create(ctx, user)
}

// UpdateUser updates an existing user
func (s *UserService) UpdateUser(ctx context.Context, user *models.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	if user.ID == 0 {
		return fmt.Errorf("user ID must be set")
	}
	return s.userRepo.Update(ctx, user)
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("user ID must be set")
	}
	return s.userRepo.Delete(ctx, id)
}

// UpdateUserRole updates a user's role
func (s *UserService) UpdateUserRole(ctx context.Context, id uint, role string) error {
	if id == 0 {
		return fmt.Errorf("user ID must be set")
	}
	if role == "" {
		return fmt.Errorf("role cannot be empty")
	}
	return s.userRepo.UpdateRole(ctx, id, role)
}

// CheckEmailExists checks if a user with given email exists
func (s *UserService) CheckEmailExists(ctx context.Context, email string) (bool, error) {
	if email == "" {
		return false, fmt.Errorf("email cannot be empty")
	}
	return s.userRepo.ExistsByEmail(ctx, email)
}
