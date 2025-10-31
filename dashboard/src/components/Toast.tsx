import React, { useEffect } from 'react'
import { X, CheckCircle, AlertCircle, Info } from 'lucide-react'

export type ToastType = 'success' | 'error' | 'info' | 'warning'

export interface ToastMessage {
  id: string
  type: ToastType
  message: string
  duration?: number
}

interface ToastProps {
  message: ToastMessage
  onClose: (id: string) => void
}

const Toast: React.FC<ToastProps> = ({ message, onClose }) => {
  useEffect(() => {
    if (message.duration && message.duration > 0) {
      const timer = setTimeout(() => {
        onClose(message.id)
      }, message.duration)
      return () => clearTimeout(timer)
    }
  }, [message, onClose])

  const styles: Record<ToastType, { bg: string; border: string; text: string; icon: React.ReactNode }> = {
    success: {
      bg: 'bg-green-900',
      border: 'border-green-700',
      text: 'text-green-100',
      icon: <CheckCircle size={20} className="text-green-400" />
    },
    error: {
      bg: 'bg-red-900',
      border: 'border-red-700',
      text: 'text-red-100',
      icon: <AlertCircle size={20} className="text-red-400" />
    },
    warning: {
      bg: 'bg-yellow-900',
      border: 'border-yellow-700',
      text: 'text-yellow-100',
      icon: <AlertCircle size={20} className="text-yellow-400" />
    },
    info: {
      bg: 'bg-blue-900',
      border: 'border-blue-700',
      text: 'text-blue-100',
      icon: <Info size={20} className="text-blue-400" />
    }
  }

  const style = styles[message.type]

  return (
    <div
      className={`${style.bg} ${style.border} ${style.text} border rounded-lg p-4 flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300`}
      role="alert"
    >
      {style.icon}
      <span className="flex-1 text-sm font-medium">{message.message}</span>
      <button
        onClick={() => onClose(message.id)}
        className="hover:opacity-75 transition"
        aria-label="Close notification"
      >
        <X size={18} />
      </button>
    </div>
  )
}

export default Toast
