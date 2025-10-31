import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react'
import { SnackbarMessage, SnackbarType } from '@/components/common/Snackbar'

interface ToastContextType {
  toasts: SnackbarMessage[]
  showToast: (message: string, type: SnackbarType, duration?: number) => void
  removeToast: (id: string) => void
}

const ToastContext = createContext<ToastContextType | undefined>(undefined)

export const ToastProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<SnackbarMessage[]>([])

  const showToast = useCallback((message: string, type: SnackbarType = 'info', duration: number = 4000) => {
    const id = Date.now().toString()
    const newToast: SnackbarMessage = { id, message, type, duration }
    setToasts(prev => [...prev, newToast])
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toasts, showToast, removeToast }}>
      {children}
    </ToastContext.Provider>
  )
}

export const useToast = () => {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}

// Alias for useToast (same functionality, different name)
export const useSnackbar = useToast
