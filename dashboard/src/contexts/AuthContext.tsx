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
  refreshToken: string | null
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  verifyOTP: (email: string, otpCode: string, backupCode?: string) => Promise<void>
  logout: () => void
  refresh: () => Promise<string>
  setupTwoFA: () => Promise<TwoFASetup>
  completeTwoFASetup: (secret: string, otpCode: string) => Promise<void>
  disableTwoFA: (password: string) => Promise<void>
  resetTwoFASetupFlag: () => void
  requiresTwoFA: boolean
  requiresTwoFASetup: boolean
  currentUserEmail: string | null
  setToken: (token: string | null) => void
  setUser: (user: User | null) => void
  setRequiresTwoFASetup: (requires: boolean) => void
  setRequiresTwoFA: (requires: boolean) => void
  setCurrentUserEmail: (email: string | null) => void
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
  const [refreshToken, setRefreshToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [requiresTwoFA, setRequiresTwoFA] = useState(false)
  const [requiresTwoFASetup, setRequiresTwoFASetup] = useState(false)
  const [currentUserEmail, setCurrentUserEmail] = useState<string | null>(null)

  // Load token and user from localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('authToken')
    const storedUser = localStorage.getItem('authUser')
    const storedRefreshToken = localStorage.getItem('authRefreshToken')

    if (storedToken && storedUser) {
      const parsedUser = JSON.parse(storedUser)
      setToken(storedToken)
      setUser(parsedUser)
      axios.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`
    }
    if (storedRefreshToken) {
      setRefreshToken(storedRefreshToken)
    }

    setIsLoading(false)
  }, [])

  const login = async (email: string, password: string) => {
    try {
      const response = await axios.post('/api/auth/login', {
        email,
        password,
      })

      if (response.data.requires_2fa_setup) {
        // User must set up 2FA before proceeding
        setRequiresTwoFASetup(true)
        setCurrentUserEmail(email)
        // Save temporary token and user for 2FA setup
        if (response.data.token) {
          setToken(response.data.token)
          setUser(response.data.user)
          localStorage.setItem('authToken', response.data.token)
          localStorage.setItem('authUser', JSON.stringify(response.data.user))
          axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`
        }
        return
      }

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
      if (response.data.refresh_token) {
        setRefreshToken(response.data.refresh_token)
        localStorage.setItem('authRefreshToken', response.data.refresh_token)
      }
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`
      setRequiresTwoFA(false)
      setRequiresTwoFASetup(false)
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
      if (response.data.refresh_token) {
        setRefreshToken(response.data.refresh_token)
        localStorage.setItem('authRefreshToken', response.data.refresh_token)
      }
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
    setRefreshToken(null)
    localStorage.removeItem('authToken')
    localStorage.removeItem('authUser')
    localStorage.removeItem('authRefreshToken')
    delete axios.defaults.headers.common['Authorization']
  }

  const refresh = async (): Promise<string> => {
    const storedRefresh = localStorage.getItem('authRefreshToken')
    if (!storedRefresh) throw new Error('No refresh token available')
    const response = await axios.post('/api/auth/refresh', { refresh_token: storedRefresh })
    const { token: newAccessToken, refresh_token: newRefreshToken } = response.data
    setToken(newAccessToken)
    localStorage.setItem('authToken', newAccessToken)
    if (newRefreshToken) {
      setRefreshToken(newRefreshToken)
      localStorage.setItem('authRefreshToken', newRefreshToken)
    }
    axios.defaults.headers.common['Authorization'] = `Bearer ${newAccessToken}`
    return newAccessToken
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
      // Reset 2FA setup flag
      setRequiresTwoFASetup(false)
    } catch (error) {
      console.error('2FA confirmation failed:', error)
      throw error
    }
  }

  const resetTwoFASetupFlag = () => {
    setRequiresTwoFASetup(false)
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
        refreshToken,
        isLoading,
        login,
        verifyOTP,
        logout,
        refresh,
        setupTwoFA,
        completeTwoFASetup,
        disableTwoFA,
        resetTwoFASetupFlag,
        requiresTwoFA,
        requiresTwoFASetup,
        currentUserEmail,
        setToken,
        setUser,
        setRequiresTwoFASetup,
        setRequiresTwoFA,
        setCurrentUserEmail,
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
