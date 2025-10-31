import React, { useEffect } from 'react'
import { X, CheckCircle, AlertCircle, Info } from 'lucide-react'

export type SnackbarType = 'success' | 'error' | 'info' | 'warning'

export interface SnackbarMessage {
  id: string
  type: SnackbarType
  message: string
  duration?: number
}

interface SnackbarProps {
  message: SnackbarMessage
  onClose: (id: string) => void
}

const Snackbar: React.FC<SnackbarProps> = ({ message, onClose }) => {
  useEffect(() => {
    if (message.duration && message.duration > 0) {
      const timer = setTimeout(() => {
        onClose(message.id)
      }, message.duration)
      return () => clearTimeout(timer)
    }
  }, [message, onClose])

  const styles: Record<SnackbarType, { bg: string; border: string; text: string; icon: React.ReactNode }> = {
    success: {
      bg: 'bg-emerald-600',
      border: 'border-emerald-500',
      text: 'text-white',
      icon: <CheckCircle size={20} />
    },
    error: {
      bg: 'bg-red-600',
      border: 'border-red-500',
      text: 'text-white',
      icon: <AlertCircle size={20} />
    },
    warning: {
      bg: 'bg-amber-600',
      border: 'border-amber-500',
      text: 'text-white',
      icon: <AlertCircle size={20} />
    },
    info: {
      bg: 'bg-blue-600',
      border: 'border-blue-500',
      text: 'text-white',
      icon: <Info size={20} />
    }
  }

  const style = styles[message.type]

  return (
    <div
      className={`${style.bg} ${style.text} rounded-lg p-4 flex items-center gap-3 shadow-lg animate-in slide-in-from-bottom duration-300 min-w-sm max-w-sm border ${style.border}`}
      role="alert"
    >
      <div className="flex-shrink-0">{style.icon}</div>
      <span className="flex-1 text-sm font-medium">{message.message}</span>
      <button
        onClick={() => onClose(message.id)}
        className="flex-shrink-0 hover:opacity-75 transition"
        aria-label="Close notification"
      >
        <X size={18} />
      </button>
    </div>
  )
}

export default Snackbar
