import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import axios from 'axios'

interface User {
  id: number
  email: string
  name: string
  role: string
  two_fa_enabled: boolean
}

interface AuthContextType {
  user: User | null
  token: string | null
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  verifyOTP: (email: string, otpCode: string, backupCode?: string) => Promise<void>
  logout: () => void
  setupTwoFA: () => Promise<TwoFASetup>
  completeTwoFASetup: (secret: string, otpCode: string) => Promise<void>
  disableTwoFA: (password: string) => Promise<void>
  requiresTwoFA: boolean
  currentUserEmail: string | null
}

interface TwoFASetup {
  qr_code_url: string
  secret: string
  backup_codes: string[]
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [requiresTwoFA, setRequiresTwoFA] = useState(false)
  const [currentUserEmail, setCurrentUserEmail] = useState<string | null>(null)

  // Load token and user from localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('authToken')
    const storedUser = localStorage.getItem('authUser')

    if (storedToken && storedUser) {
      setToken(storedToken)
      setUser(JSON.parse(storedUser))
      // Set default auth header
      axios.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`
    }

    setIsLoading(false)
  }, [])

  const login = async (email: string, password: string) => {
    try {
      const response = await axios.post('/api/auth/login', {
        email,
        password,
      })

      if (response.data.requires_2fa) {
        // User has 2FA enabled, wait for OTP
        setRequiresTwoFA(true)
        setCurrentUserEmail(email)
        return
      }

      // No 2FA, login successful
      setToken(response.data.token)
      setUser(response.data.user)
      localStorage.setItem('authToken', response.data.token)
      localStorage.setItem('authUser', JSON.stringify(response.data.user))
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`
      setRequiresTwoFA(false)
    } catch (error) {
      console.error('Login failed:', error)
      throw error
    }
  }

  const verifyOTP = async (email: string, otpCode: string, backupCode?: string) => {
    try {
      const response = await axios.post('/api/auth/verify-otp', {
        email,
        otp_code: otpCode || '',
        backup_code: backupCode || '',
      })

      setToken(response.data.token)
      setUser(response.data.user)
      localStorage.setItem('authToken', response.data.token)
      localStorage.setItem('authUser', JSON.stringify(response.data.user))
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`
      setRequiresTwoFA(false)
      setCurrentUserEmail(null)
    } catch (error) {
      console.error('OTP verification failed:', error)
      throw error
    }
  }

  // register removed: admin-only user creation handled by admin UI

  const logout = () => {
    setUser(null)
    setToken(null)
    localStorage.removeItem('authToken')
    localStorage.removeItem('authUser')
    delete axios.defaults.headers.common['Authorization']
  }

  const setupTwoFA = async (): Promise<TwoFASetup> => {
    try {
      const response = await axios.post('/api/auth/2fa/setup')
      return response.data
    } catch (error) {
      console.error('2FA setup failed:', error)
      throw error
    }
  }

  const completeTwoFASetup = async (secret: string, otpCode: string) => {
    try {
      await axios.post('/api/auth/2fa/confirm', {
        secret,
        otp_code: otpCode,
      })
      // Update user info
      if (user) {
        setUser({ ...user, two_fa_enabled: true })
        localStorage.setItem('authUser', JSON.stringify({ ...user, two_fa_enabled: true }))
      }
    } catch (error) {
      console.error('2FA confirmation failed:', error)
      throw error
    }
  }

  const disableTwoFA = async (password: string) => {
    try {
      await axios.post('/api/auth/2fa/disable', {
        password,
      })
      // Update user info
      if (user) {
        setUser({ ...user, two_fa_enabled: false })
        localStorage.setItem('authUser', JSON.stringify({ ...user, two_fa_enabled: false }))
      }
    } catch (error) {
      console.error('2FA disable failed:', error)
      throw error
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        login,
        verifyOTP,
  // register removed: admin should create users
        logout,
        setupTwoFA,
        completeTwoFASetup,
        disableTwoFA,
        requiresTwoFA,
        currentUserEmail,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
