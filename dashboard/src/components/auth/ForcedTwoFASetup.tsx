import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import QRCode from 'qrcode'
import { RefreshCw, Clipboard, Download } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { useToast } from '@/contexts/SnackbarContext'

const ForcedTwoFASetup: React.FC = () => {
  const navigate = useNavigate()
  const { setupTwoFA } = useAuth()
  const { showToast } = useToast()

  const [twoFASecret, setTwoFASecret] = useState<string>('')
  const [twoFAOtpauth, setTwoFAOtpauth] = useState<string>('')
  const [twoFAOtpCode, setTwoFAOtpCode] = useState<string>('')
  const [twoFAError, setTwoFAError] = useState<string>('')
  const [twoFALoading, setTwoFALoading] = useState<boolean>(false)
  const [qrDataUrl, setQrDataUrl] = useState<string>('')
  const [isInitializing, setIsInitializing] = useState<boolean>(true)
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [setupComplete, setSetupComplete] = useState<boolean>(false)

  // Generate QR code
  useEffect(() => {
    let mounted = true
    const build = async () => {
      if (!twoFAOtpauth) {
        setQrDataUrl('')
        return
      }
      try {
        const dataUrl = await QRCode.toDataURL(twoFAOtpauth, { margin: 1, width: 200 })
        if (mounted) setQrDataUrl(dataUrl)
      } catch (err) {
        console.error('Failed to generate QR', err)
        if (mounted) setQrDataUrl('')
      }
    }
    build()
    return () => { mounted = false }
  }, [twoFAOtpauth])

  // Initialize 2FA setup on mount
  useEffect(() => {
    const init = async () => {
      setTwoFAError('')
      setIsInitializing(true)
      try {
        const token = localStorage.getItem('authToken')
        if (!token) {
          throw new Error('No token found. Please login first.')
        }
        const response = await fetch('/api/auth/2fa/setup', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        })
        if (!response.ok) {
          throw new Error('Failed to initialize 2FA setup')
        }
        const data = await response.json()
        setTwoFASecret(data.secret || '')
        setTwoFAOtpauth(data.qr_code_url || '')
      } catch (e: any) {
        setTwoFAError(e?.message || 'Error initializing 2FA setup')
      } finally {
        setIsInitializing(false)
      }
    }
    init()
  }, [])

  const copySecret = async () => {
    if (!twoFASecret) return
    try {
      await navigator.clipboard.writeText(twoFASecret)
      showToast('Secret copied to clipboard', 'success')
    } catch (e) {
      showToast('Failed to copy secret', 'error')
    }
  }

  const regenerateSecret = async () => {
    setTwoFAError('')
    setTwoFALoading(true)
    try {
      const data = await setupTwoFA()
      setTwoFASecret(data.secret || '')
      setTwoFAOtpauth(data.qr_code_url || '')
      setTwoFAOtpCode('')
    } catch (e: any) {
      setTwoFAError(e?.message || 'Error regenerating secret')
    } finally {
      setTwoFALoading(false)
    }
  }

  const confirmSetup = async () => {
    setTwoFAError('')
    setTwoFALoading(true)
    try {
      if (!twoFASecret) {
        throw new Error('Secret not initialized')
      }
      const response = await fetch('/api/auth/2fa/confirm', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ secret: twoFASecret, otp_code: twoFAOtpCode }),
      })

      if (!response.ok) {
        const err = await response.json().catch(() => ({}))
        throw new Error(err?.error || 'Error confirming 2FA setup')
      }

      const data = await response.json()
      setBackupCodes(data.backup_codes || [])
      setSetupComplete(true)
    } catch (e: any) {
      setTwoFAError(e?.message || 'Error confirming 2FA setup')
    } finally {
      setTwoFALoading(false)
    }
  }

  const downloadBackupCodes = () => {
    const content = backupCodes.join('\n')
    const element = document.createElement('a')
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content))
    element.setAttribute('download', 'waf-dashboard-backup-codes.txt')
    element.style.display = 'none'
    document.body.appendChild(element)
    element.click()
    document.body.removeChild(element)
  }

  const copyBackupCodes = async () => {
    try {
      await navigator.clipboard.writeText(backupCodes.join('\n'))
      showToast('Backup codes copied to clipboard', 'success')
    } catch (e) {
      showToast('Failed to copy backup codes', 'error')
    }
  }

  const continueToDashboard = () => {
    navigate('/dashboard')
  }

  // Show backup codes screen after successful setup
  if (setupComplete) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900 p-4">
        <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-lg border border-gray-700">
          <h1 className="text-2xl font-bold text-white mb-2 text-center">Setup Complete!</h1>
          <p className="text-gray-400 text-center mb-6 text-sm">
            Your two-factor authentication is now enabled.
          </p>

          {/* Backup Codes Section */}
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-white mb-3">Save Your Backup Codes</h3>
            <p className="text-gray-400 text-sm mb-3">
              These codes can be used to access your account if you lose access to your authenticator app. Each code can be used only once. Keep them in a safe place.
            </p>

            <div className="bg-gray-900 border border-gray-700 rounded p-4 mb-4 max-h-48 overflow-y-auto">
              <div className="grid grid-cols-2 gap-2">
                {backupCodes.map((code, idx) => (
                  <div key={idx} className="font-mono text-sm text-gray-300 bg-gray-800 px-3 py-2 rounded border border-gray-700">
                    {code}
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-2 mb-6">
              <button
                onClick={copyBackupCodes}
                className="flex-1 flex items-center justify-center gap-2 bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded transition"
              >
                <Clipboard size={16} />
                Copy
              </button>
              <button
                onClick={downloadBackupCodes}
                className="flex-1 flex items-center justify-center gap-2 bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded transition"
              >
                <Download size={16} />
                Download
              </button>
            </div>
          </div>

          {/* Warning Box */}
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-4 mb-6">
            <p className="text-xs text-yellow-200">
              <span className="font-semibold">⚠️ Important:</span> Make sure you've saved your backup codes and that your authenticator app is working before continuing. You won't be able to see these codes again.
            </p>
          </div>

          {/* Continue Button */}
          <button
            onClick={continueToDashboard}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition"
          >
            Continue to Dashboard
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 p-4">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md border border-gray-700">
        <h1 className="text-2xl font-bold text-white mb-2 text-center">Set Up Two-Factor Authentication</h1>
        <p className="text-gray-400 text-center mb-6 text-sm">
          Two-factor authentication is required for your account. Please set it up now.
        </p>

        {isInitializing ? (
          <div className="text-center py-8">
            <div className="text-gray-400">Initializing...</div>
          </div>
        ) : (
          <>
            {/* QR Code Section */}
            {qrDataUrl && (
              <div className="mb-6 text-center">
                <p className="text-gray-300 text-sm mb-3">
                  Scan this QR code with your authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)
                </p>
                <img
                  src={qrDataUrl}
                  alt="2FA QR code"
                  className="w-40 h-40 border border-gray-700 rounded mx-auto"
                />
                <p className="text-xs text-gray-500 mt-2">
                  If your app can't scan the code, use the manual secret below
                </p>
              </div>
            )}

            {/* Manual Secret Section */}
            {twoFASecret && (
              <div className="mb-6">
                <label className="block text-gray-400 text-xs font-medium mb-2">Manual Secret</label>
                <div className="flex items-center gap-2">
                  <input
                    readOnly
                    value={twoFASecret}
                    className="flex-1 px-3 py-2 bg-gray-900 text-gray-200 text-sm rounded border border-gray-600 focus:outline-none font-mono"
                  />
                  <button
                    onClick={copySecret}
                    title="Copy secret"
                    className="h-10 w-10 flex items-center justify-center bg-gray-700 hover:bg-gray-600 rounded transition"
                  >
                    <Clipboard size={16} />
                  </button>
                  <button
                    onClick={regenerateSecret}
                    disabled={twoFALoading}
                    title="Regenerate"
                    className="h-10 w-10 flex items-center justify-center bg-gray-700 hover:bg-gray-600 rounded transition disabled:opacity-50"
                  >
                    <RefreshCw size={16} />
                  </button>
                </div>
              </div>
            )}

            {/* OTP Code Input */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Enter 6-digit code from your authenticator app
              </label>
              <input
                type="text"
                value={twoFAOtpCode}
                onChange={(e) => setTwoFAOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500 text-center text-2xl tracking-widest"
              />
            </div>

            {/* Error Message */}
            {twoFAError && (
              <div className="bg-red-500/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-4 text-sm">
                {twoFAError}
              </div>
            )}

            {/* Confirm Button */}
            <button
              onClick={confirmSetup}
              disabled={twoFALoading || twoFAOtpCode.length < 6}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-bold py-2 px-4 rounded transition"
            >
              {twoFALoading ? 'Confirming...' : 'Confirm & Continue'}
            </button>

            {/* Info Box */}
            <div className="mt-6 bg-gray-900 border border-gray-700 rounded p-4">
              <p className="text-xs text-gray-400">
                <span className="font-semibold text-gray-300">Save your backup codes:</span> After setup, you'll receive backup codes. Keep them in a safe place in case you lose access to your authenticator app.
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default ForcedTwoFASetup
