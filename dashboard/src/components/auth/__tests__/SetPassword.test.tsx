// SetPassword.test.tsx
import React from 'react'
import { describe, it, expect, vi, beforeEach, Mock } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, useNavigate, useSearchParams } from 'react-router-dom'
import axios from 'axios'
import SetPassword from '../SetPassword'
import { useAuth } from '@/contexts/AuthContext'

// Mock delle dipendenze
vi.mock('axios')
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: vi.fn(),
    useSearchParams: vi.fn(),
  }
})

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}))

// Mock di lucide-react
vi.mock('lucide-react', () => ({
  Eye: () => <svg data-testid="eye-icon" />,
  EyeOff: () => <svg data-testid="eyeoff-icon" />,
}))

const mockedAxios = axios as Mock
const mockedNavigate = vi.fn()
const mockSetAuthToken = vi.fn()
const mockSetUser = vi.fn()
const mockSetRequiresTwoFASetup = vi.fn()

// Mock di useAuth
const mockUseAuth = vi.mocked(useAuth)

describe('SetPassword Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    
    // Setup mocks
    vi.mocked(useNavigate).mockReturnValue(mockedNavigate)
    vi.mocked(useSearchParams).mockReturnValue([
      new URLSearchParams('token=test-token'),
      vi.fn()
    ])
    mockUseAuth.mockReturnValue({
      setToken: mockSetAuthToken,
      setUser: mockSetUser,
      setRequiresTwoFASetup: mockSetRequiresTwoFASetup,
    })

    // Mock axios
    mockedAxios.post.mockReset()
    
    // Mock localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        setItem: vi.fn(),
        getItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      },
      writable: true
    })
  })

  // Test 1: Renderizzazione base
  it('renders the set password form correctly', () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    expect(screen.getByText('Set your password')).toBeInTheDocument()
    expect(screen.getByLabelText(/new password/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set password/i })).toBeInTheDocument()
  })

  // Test 2: Mostra errore quando manca il token
  it('shows error when token is missing', async () => {
    // Mock senza token
    vi.mocked(useSearchParams).mockReturnValue([
      new URLSearchParams(''),
      vi.fn()
    ])

    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'Password123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    expect(await screen.findByText(/missing token/i)).toBeInTheDocument()
  })

  // Test 3: Validazione password troppo corta
  it('shows error when password is too short', async () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: '123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: '123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    expect(await screen.findByText(/password too short/i)).toBeInTheDocument()
  })

  // Test 4: Validazione password non corrispondenti
  it('shows error when passwords do not match', async () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'DifferentPassword123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument()
  })

  // Test 5: Toggle visibilità password - VERSIONE CORRETTA
  it('toggles password visibility', async () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    const passwordInput = screen.getByLabelText(/new password/i)
    const confirmInput = screen.getByLabelText(/confirm password/i)
    
    // Trova i bottoni di toggle
    const toggleButtons = screen.getAllByRole('button', { name: '' }) // Bottoni senza testo
    const newPasswordToggle = toggleButtons[0]
    const confirmPasswordToggle = toggleButtons[1]

    // Inizialmente dovrebbero essere type="password"
    expect(passwordInput).toHaveAttribute('type', 'password')
    expect(confirmInput).toHaveAttribute('type', 'password')

    // Clicca per mostrare la prima password
    fireEvent.click(newPasswordToggle)
    expect(passwordInput).toHaveAttribute('type', 'text')
    expect(confirmInput).toHaveAttribute('type', 'password')

    // Clicca per nascondere la prima password
    fireEvent.click(newPasswordToggle)
    expect(passwordInput).toHaveAttribute('type', 'password')

    // Clicca per mostrare la seconda password
    fireEvent.click(confirmPasswordToggle)
    expect(confirmInput).toHaveAttribute('type', 'text')

    // Clicca per nascondere la seconda password
    fireEvent.click(confirmPasswordToggle)
    expect(confirmInput).toHaveAttribute('type', 'password')
  })

  // Test 6: Invio form con successo
  it('successfully submits form and redirects', async () => {
    const mockResponse = {
      data: {
        token: 'jwt-token-123',
        user: { id: 1, email: 'test@example.com' },
        requires_2fa_setup: true,
      }
    }

    mockedAxios.post.mockResolvedValue(mockResponse)

    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'Password123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    // Verifica chiamata API
    expect(mockedAxios.post).toHaveBeenCalledWith('/api/auth/set-password', {
      token: 'test-token',
      new_password: 'Password123'
    })

    // Verifica messaggio di successo
    expect(await screen.findByText(/password set/i)).toBeInTheDocument()

    // Verifica salvataggio token e user
    expect(window.localStorage.setItem).toHaveBeenCalledWith('authToken', 'jwt-token-123')
    expect(window.localStorage.setItem).toHaveBeenCalledWith('authUser', JSON.stringify(mockResponse.data.user))
    
    // Verifica chiamate context
    expect(mockSetAuthToken).toHaveBeenCalledWith('jwt-token-123')
    expect(mockSetUser).toHaveBeenCalledWith(mockResponse.data.user)
    expect(mockSetRequiresTwoFASetup).toHaveBeenCalledWith(true)

    // Verifica redirect
    await waitFor(() => {
      expect(mockedNavigate).toHaveBeenCalledWith('/setup-2fa')
    }, { timeout: 2000 })
  })

  // Test 7: Gestione errore API
  it('handles API error', async () => {
    mockedAxios.post.mockRejectedValue({
      response: {
        data: { error: 'Token expired' }
      }
    })

    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'Password123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    expect(await screen.findByText(/token expired/i)).toBeInTheDocument()
  })

  // Test 8: Gestione errore generico API
  it('handles generic API error', async () => {
    mockedAxios.post.mockRejectedValue(new Error('Network error'))

    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'Password123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    expect(await screen.findByText(/failed/i)).toBeInTheDocument()
  })

  // Test 9: Reset errori al submit
  it('clears errors on form submission', async () => {
    // Prima imposta un errore
    mockedAxios.post.mockRejectedValueOnce({
      response: { data: { error: 'Token expired' } }
    })

    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    // Primo submit con errore
    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'Password123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))
    
    await screen.findByText(/token expired/i)

    // Simula un successo al secondo tentativo
    mockedAxios.post.mockResolvedValueOnce({
      data: {
        token: 'new-token',
        user: { id: 1, email: 'test@example.com' },
        requires_2fa_setup: true,
      }
    })

    // Secondo submit
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    // L'errore dovrebbe scomparire e apparire il successo
    await waitFor(() => {
      expect(screen.queryByText(/token expired/i)).not.toBeInTheDocument()
      expect(screen.getByText(/password set/i)).toBeInTheDocument()
    })
  })

  // Test 10: Configurazione header Authorization
  it('sets axios authorization header on success', async () => {
    const mockResponse = {
      data: {
        token: 'jwt-token-123',
        user: { id: 1, email: 'test@example.com' },
        requires_2fa_setup: true,
      }
    }

    mockedAxios.post.mockResolvedValue(mockResponse)

    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    fireEvent.change(screen.getByLabelText(/new password/i), { 
      target: { value: 'Password123' } 
    })
    fireEvent.change(screen.getByLabelText(/confirm password/i), { 
      target: { value: 'Password123' } 
    })
    
    fireEvent.click(screen.getByRole('button', { name: /set password/i }))

    await waitFor(() => {
      expect(axios.defaults.headers.common['Authorization']).toBe('Bearer jwt-token-123')
    })
  })

  // Test 11: Verifica struttura del form - VERSIONE CORRETTA
  it('has proper form structure', () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    // Il form è un elemento <form> ma non ha role="form"
    // Cerchiamo l'elemento form in modo diverso
    const form = document.querySelector('form')
    expect(form).toBeInTheDocument()
    expect(form).toHaveClass('space-y-4')
    
    const passwordInput = screen.getByLabelText(/new password/i)
    const confirmInput = screen.getByLabelText(/confirm password/i)
    
    expect(passwordInput).toHaveAttribute('type', 'password')
    expect(confirmInput).toHaveAttribute('type', 'password')
  })

  // Test 12: Verifica classi CSS
  it('has correct CSS classes', () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    const title = screen.getByText('Set your password')
    // Il titolo è dentro un div con classe bg-gray-800
    const container = screen.getByText('Set your password').closest('.bg-gray-800')
    expect(container).toBeInTheDocument()
    
    const button = screen.getByRole('button', { name: /set password/i })
    expect(button).toHaveClass('bg-blue-600')
  })

  // Test aggiuntivo: Verifica che i bottoni toggle siano presenti
  it('has toggle buttons for password visibility', () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    // Ci dovrebbero essere 3 bottoni: 2 toggle e 1 submit
    const buttons = screen.getAllByRole('button')
    expect(buttons).toHaveLength(3) // 2 toggle + 1 submit
    
    // I toggle buttons dovrebbero essere di tipo button
    const toggleButtons = buttons.slice(0, 2) // I primi 2 sono i toggle
    toggleButtons.forEach(button => {
      expect(button).toHaveAttribute('type', 'button')
    })
  })

  // Test aggiuntivo: Verifica che gli input siano vuoti all'inizio
  it('has empty inputs initially', () => {
    render(
      <MemoryRouter>
        <SetPassword />
      </MemoryRouter>
    )

    const passwordInput = screen.getByLabelText(/new password/i)
    const confirmInput = screen.getByLabelText(/confirm password/i)
    
    expect(passwordInput).toHaveValue('')
    expect(confirmInput).toHaveValue('')
  })
})