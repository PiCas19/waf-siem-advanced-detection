import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Users from '../Users';
import * as AuthContext from '@/contexts/AuthContext';
import * as SnackbarContext from '@/contexts/SnackbarContext';
import axios from 'axios';

vi.mock('axios');
vi.mock('@/contexts/AuthContext', () => ({ useAuth: vi.fn() }));
vi.mock('@/contexts/SnackbarContext', () => ({ useSnackbar: vi.fn() }));

const mockUsers = [
  { id: 1, email: 'admin@test.com', name: 'Admin User', role: 'admin', active: true, two_fa_enabled: true, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' },
  { id: 2, email: 'user@test.com', name: 'Regular User', role: 'user', active: true, two_fa_enabled: false, created_at: '2024-01-02T00:00:00Z', updated_at: '2024-01-02T00:00:00Z' },
  { id: 3, email: 'operator@test.com', name: 'Operator User', role: 'operator', active: false, two_fa_enabled: true, created_at: '2024-01-03T00:00:00Z', updated_at: '2024-01-03T00:00:00Z' },
];

describe('Users Component', () => {
  const mockShowToast = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    (SnackbarContext.useSnackbar as any).mockReturnValue({ showToast: mockShowToast });
    (AuthContext.useAuth as any).mockReturnValue({
      token: 'test-token',
      user: { id: 1, email: 'admin@test.com', role: 'admin' },
      isLoading: false,
    });
  });

  // Basic render
  it('renders User Management title', () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    expect(screen.getByText('User Management')).toBeInTheDocument();
  });

  it('loads and displays users', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => expect(screen.getByText('admin@test.com')).toBeInTheDocument());
    expect(screen.getByText('Regular User')).toBeInTheDocument();
  });

  it('shows loading state while fetching users', () => {
    (axios.get as any).mockImplementation(() => new Promise(() => {}));
    render(<BrowserRouter><Users /></BrowserRouter>);
    expect(screen.getByText('Loading users...')).toBeInTheDocument();
  });

  it('shows error message on load failure', async () => {
    (axios.get as any).mockRejectedValue({ response: { data: { error: 'Failed to fetch users' } } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => expect(screen.getByText('Failed to fetch users')).toBeInTheDocument());
  });

  // Create user
  it('toggles create user form and creates user successfully', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.post as any).mockResolvedValue({ data: { success: true } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('+ Add User'));

    fireEvent.click(screen.getByText('+ Add User'));
    expect(screen.getByText('Create New User')).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText('user@example.com'), { target: { value: 'newuser@test.com' } });
    fireEvent.change(screen.getByPlaceholderText('John Doe'), { target: { value: 'New User' } });
    fireEvent.change(screen.getByTestId('create-user-role'), { target: { value: 'analyst' } });
    fireEvent.click(screen.getByText('Create User'));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        '/api/admin/users',
        { email: 'newuser@test.com', name: 'New User', role: 'analyst' },
        { headers: { Authorization: 'Bearer test-token' } }
      );
    });
    expect(mockShowToast).toHaveBeenCalledWith('User created successfully!', 'success');
  });

  it('shows error toast if create user fails', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.post as any).mockRejectedValue({ response: { data: { error: 'Email already exists' } } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('+ Add User'));
    fireEvent.click(screen.getByText('+ Add User'));

    fireEvent.change(screen.getByPlaceholderText('user@example.com'), { target: { value: 'admin@test.com' } });
    fireEvent.change(screen.getByPlaceholderText('John Doe'), { target: { value: 'Admin' } });
    fireEvent.change(screen.getByTestId('create-user-role'), { target: { value: 'admin' } });

    fireEvent.click(screen.getByText('Create User'));
    await waitFor(() => expect(mockShowToast).toHaveBeenCalledWith('Email already exists', 'error'));
  });

  // Edit user
  it('opens edit modal and saves user successfully', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.put as any).mockResolvedValue({ data: { success: true } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    fireEvent.click(screen.getAllByTitle('Edit user')[0]);
    await waitFor(() => screen.getByText('Edit User'));

    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(axios.put).toHaveBeenCalled());
    expect(mockShowToast).toHaveBeenCalledWith('User updated successfully!', 'success');
  });

  it('shows error toast if edit user fails', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.put as any).mockRejectedValue({ response: { data: { error: 'Update failed' } } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));
    fireEvent.click(screen.getAllByTitle('Edit user')[0]);
    await waitFor(() => screen.getByText('Edit User'));

    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(mockShowToast).toHaveBeenCalledWith('Update failed', 'error'));
  });

  // Delete user
  it('opens delete confirmation and deletes user successfully', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.delete as any).mockResolvedValue({ data: { success: true } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    fireEvent.click(screen.getAllByTitle('Delete user')[0]);
    await waitFor(() => screen.getByText('Confirm Delete'));

    fireEvent.click(screen.getByText('Delete'));
    await waitFor(() => expect(axios.delete).toHaveBeenCalled());
    expect(mockShowToast).toHaveBeenCalledWith('User deleted successfully!', 'success');
  });

  it('shows error toast if delete user fails', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.delete as any).mockRejectedValue({ response: { data: { error: 'Delete failed' } } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    fireEvent.click(screen.getAllByTitle('Delete user')[0]);
    await waitFor(() => screen.getByText('Confirm Delete'));

    fireEvent.click(screen.getByText('Delete'));
    await waitFor(() => expect(mockShowToast).toHaveBeenCalledWith('Delete failed', 'error'));
  });

  // Filtering & sorting
  it('filters users by search term and role', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);

    await waitFor(() => screen.getByText('admin@test.com'));

    // Filtro per nome
    fireEvent.change(screen.getByPlaceholderText('Search by email or name...'), { target: { value: 'Regular' } });
    await waitFor(() => {
      expect(screen.getByText('Regular User')).toBeInTheDocument();
      expect(screen.queryByText('Admin User')).not.toBeInTheDocument();
    });

    // Resetta il campo di ricerca prima di filtrare per ruolo
    fireEvent.change(screen.getByPlaceholderText('Search by email or name...'), { target: { value: '' } });

    // Filtro per ruolo
    const roleSelect = screen.getByRole('combobox');
    fireEvent.change(roleSelect, { target: { value: 'operator' } });
    await waitFor(() => {
      expect(screen.getByText('Operator User')).toBeInTheDocument();
      expect(screen.queryByText('Admin User')).not.toBeInTheDocument();
    });
  });


  it('sorts users by email with correct icon', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('admin@test.com'));

    const emailHeader = screen.getByText(/Email/);
    fireEvent.click(emailHeader);
    expect(screen.getByText('↑')).toBeInTheDocument();
    fireEvent.click(emailHeader);
    expect(screen.getByText('↓')).toBeInTheDocument();
  });

  // Pagination
  it('paginates users correctly and disables buttons on edges', async () => {
    const manyUsers = Array.from({ length: 15 }, (_, i) => ({
      id: i + 1, email: `user${i + 1}@test.com`, name: `User ${i + 1}`, role: 'user',
      active: true, two_fa_enabled: false, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z',
    }));
    (axios.get as any).mockResolvedValue({ data: { data: manyUsers } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user1@test.com'));

    const prevButton = screen.getByText('Previous') as HTMLButtonElement;
    const nextButton = screen.getByText('Next') as HTMLButtonElement;

    expect(prevButton).toBeDisabled();
    expect(nextButton).not.toBeDisabled();

    fireEvent.click(screen.getByText('2'));
    await waitFor(() => screen.getByText('user11@test.com'));
    expect(nextButton).toBeDisabled();
  });

  // Visual badges
  it('displays role badges and statuses correctly', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('admin@test.com'));

    expect(screen.getByText('admin')).toHaveClass('bg-red-900', 'text-red-100');
    expect(screen.getByText('user')).toHaveClass('bg-gray-700', 'text-gray-100');
    expect(screen.getByText('operator')).toHaveClass('bg-blue-900', 'text-blue-100');

    expect(screen.getAllByText('✓ Active').length).toBe(2);
    expect(screen.getAllByText('✗ Inactive').length).toBe(1);

    expect(screen.getAllByText('✓ Enabled').length).toBe(2);
    expect(screen.getAllByText('✗ Disabled').length).toBe(1);
  });

  // Empty and old API format
  it('shows no users message for empty list', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: [] } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('No users found'));
  });

  it('handles old API format', async () => {
    (axios.get as any).mockResolvedValue({ data: { users: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('admin@test.com'));
  });

  // Self edit/delete protection
  it('disables edit/delete buttons for current user', async () => {
    (AuthContext.useAuth as any).mockReturnValue({
      token: 'test-token',
      user: { id: 2, email: 'user@test.com', role: 'user' },
      isLoading: false,
    });
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    expect(screen.getAllByTitle('Cannot edit your own account').length).toBeGreaterThan(0);
    expect(screen.getAllByTitle('Cannot delete your own account').length).toBeGreaterThan(0);
  });

  // NUOVI TEST PER COPRIRE LINEE 283, 347-361, 435, 457-535

  it('closes create user form when Close button is clicked (LINEA 283)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('+ Add User'));

    // Apri il form
    fireEvent.click(screen.getByText('+ Add User'));
    expect(screen.getByText('Create New User')).toBeInTheDocument();

    // LINEA 283: Click sul bottone Close
    fireEvent.click(screen.getByText('Close'));

    // Il form dovrebbe essere chiuso
    await waitFor(() => {
      expect(screen.queryByText('Create New User')).not.toBeInTheDocument();
    });
  });

  it('sorts users by name when Name header is clicked (LINEA 347-350)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('admin@test.com'));

    // LINEA 347-350: Click sull'header Name per ordinare
    const nameHeader = screen.getByText('Name');
    fireEvent.click(nameHeader);

    // Verifica che la sorting sia avvenuta (icona cambiata)
    await waitFor(() => {
      expect(screen.getByText('↑')).toBeInTheDocument();
    });

    // Click di nuovo per invertire l'ordine
    fireEvent.click(nameHeader);
    await waitFor(() => {
      expect(screen.getByText('↓')).toBeInTheDocument();
    });
  });

  it('sorts users by role when Role header is clicked (LINEA 353-356)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('admin@test.com'));

    // LINEA 353-356: Click sull'header Role per ordinare
    const roleHeader = screen.getByText(/^Role/);
    fireEvent.click(roleHeader);

    // Verifica che la sorting sia avvenuta
    await waitFor(() => {
      expect(screen.getByText('↑')).toBeInTheDocument();
    });

    // Click di nuovo per invertire l'ordine
    fireEvent.click(roleHeader);
    await waitFor(() => {
      expect(screen.getByText('↓')).toBeInTheDocument();
    });
  });

  it('sorts users by created_at when Created header is clicked (LINEA 361)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('admin@test.com'));

    // LINEA 361: Click sull'header Created per ordinare
    const createdHeader = screen.getByText(/Created/);
    fireEvent.click(createdHeader);

    // Verifica che la sorting sia avvenuta
    await waitFor(() => {
      expect(screen.getByText('↑')).toBeInTheDocument();
    });
  });

  it('decrements current page when Previous button is clicked (LINEA 435)', async () => {
    const manyUsers = Array.from({ length: 15 }, (_, i) => ({
      id: i + 1, email: `user${i + 1}@test.com`, name: `User ${i + 1}`, role: 'user',
      active: true, two_fa_enabled: false, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z',
    }));
    (axios.get as any).mockResolvedValue({ data: { data: manyUsers } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user1@test.com'));

    // Vai alla pagina 2
    fireEvent.click(screen.getByText('2'));
    await waitFor(() => screen.getByText('user11@test.com'));

    const prevButton = screen.getByText('Previous');

    // LINEA 435: Click sul bottone Previous
    fireEvent.click(prevButton);

    // Dovrebbe tornare alla pagina 1
    await waitFor(() => {
      expect(screen.getByText('user1@test.com')).toBeInTheDocument();
    });
  });

  it('increments current page when Next button is clicked (LINEA 457)', async () => {
    const manyUsers = Array.from({ length: 15 }, (_, i) => ({
      id: i + 1, email: `user${i + 1}@test.com`, name: `User ${i + 1}`, role: 'user',
      active: true, two_fa_enabled: false, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z',
    }));
    (axios.get as any).mockResolvedValue({ data: { data: manyUsers } });

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user1@test.com'));

    const nextButton = screen.getByText('Next');

    // LINEA 457: Click sul bottone Next
    fireEvent.click(nextButton);

    // Dovrebbe andare alla pagina 2
    await waitFor(() => {
      expect(screen.getByText('user11@test.com')).toBeInTheDocument();
    });
  });

  it('closes delete confirmation modal when Cancel is clicked (LINEE 482-485)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    // Apri il modal di conferma delete
    fireEvent.click(screen.getAllByTitle('Delete user')[0]);
    await waitFor(() => screen.getByText('Confirm Delete'));
    expect(screen.getByText('Are you sure you want to delete this user? This action cannot be undone.')).toBeInTheDocument();

    // LINEE 482-485: Click sul bottone Cancel
    const cancelButton = screen.getAllByText('Cancel')[0];
    fireEvent.click(cancelButton);

    // Il modal dovrebbe essere chiuso
    await waitFor(() => {
      expect(screen.queryByText('Confirm Delete')).not.toBeInTheDocument();
    });
  });

  it('displays delete confirmation modal with correct text (LINEE 468-493)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    // Apri il modal di conferma delete
    fireEvent.click(screen.getAllByTitle('Delete user')[0]);

    // LINEE 468-493: Verifica che il modal sia visualizzato correttamente
    await waitFor(() => {
      expect(screen.getByText('Confirm Delete')).toBeInTheDocument();
      expect(screen.getByText('Are you sure you want to delete this user? This action cannot be undone.')).toBeInTheDocument();
      expect(screen.getByText('Delete')).toBeInTheDocument();
    });
  });

  it('closes edit modal when Cancel button is clicked (LINEE 533-535)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    // Apri il modal di edit
    fireEvent.click(screen.getAllByTitle('Edit user')[0]);
    await waitFor(() => screen.getByText('Edit User'));

    // LINEE 533-535: Click sul bottone Cancel nell'edit modal
    const cancelButtons = screen.getAllByText('Cancel');
    const editCancelButton = cancelButtons.find(btn =>
      btn.parentElement?.parentElement?.parentElement?.querySelector('[class*="Edit User"]')
    ) || cancelButtons[cancelButtons.length - 1];

    fireEvent.click(editCancelButton);

    // Il modal dovrebbe essere chiuso
    await waitFor(() => {
      expect(screen.queryByText('Edit User')).not.toBeInTheDocument();
    });
  });

  it('displays Save button in edit modal and shows loading state (LINEE 525-530)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.put as any).mockImplementation(() => new Promise(() => {})); // Never resolves to keep loading

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    fireEvent.click(screen.getAllByTitle('Edit user')[0]);
    await waitFor(() => screen.getByText('Edit User'));

    const saveButton = screen.getByText('Save') as HTMLButtonElement;
    expect(saveButton).toBeInTheDocument();

    // LINEE 525-530: Click Save e verifica lo stato loading
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(screen.getByText('Saving...')).toBeInTheDocument();
    });
  });
  it('displays Deleting... text when delete is in progress (LINEA 479)', async () => {
    (axios.get as any).mockResolvedValue({ data: { data: mockUsers } });
    (axios.delete as any).mockImplementation(() => new Promise(() => {})); // Never resolves

    render(<BrowserRouter><Users /></BrowserRouter>);
    await waitFor(() => screen.getByText('user@test.com'));

    fireEvent.click(screen.getAllByTitle('Delete user')[0]);
    await waitFor(() => screen.getByText('Confirm Delete'));

    // LINEA 479: Click Delete e verifica lo stato loading
    fireEvent.click(screen.getByText('Delete'));

    await waitFor(() => {
      expect(screen.getByText('Deleting...')).toBeInTheDocument();
    });
  });

});
