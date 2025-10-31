import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react'
import { ToastMessage, ToastType } from '@/components/Toast'

interface ToastContextType {
  toasts: ToastMessage[]
  showToast: (message: string, type: ToastType, duration?: number) => void
  removeToast: (id: string) => void
}

const ToastContext = createContext<ToastContextType | undefined>(undefined)

export const ToastProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  const showToast = useCallback((message: string, type: ToastType = 'info', duration: number = 4000) => {
    const id = Date.now().toString()
    const newToast: ToastMessage = { id, message, type, duration }
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
