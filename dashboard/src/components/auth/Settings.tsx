import React, { useEffect, useMemo, useState } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import { RefreshCw, Clipboard } from 'lucide-react'

const Settings: React.FC = () => {
  const { user } = useAuth()
  const navigate = useNavigate()

  // 2FA state
  const [isTwoFAEnabled, setIsTwoFAEnabled] = useState<boolean>(!!user?.two_fa_enabled)
  const [isSettingUp2FA, setIsSettingUp2FA] = useState<boolean>(false)
  const [twoFASecret, setTwoFASecret] = useState<string>('')
  const [twoFAOtpauth, setTwoFAOtpauth] = useState<string>('')
  const [twoFAOtpCode, setTwoFAOtpCode] = useState<string>('')
  const [twoFAError, setTwoFAError] = useState<string>('')
  const [twoFALoading, setTwoFALoading] = useState<boolean>(false)

  // Change password state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmNewPassword, setConfirmNewPassword] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwLoading, setPwLoading] = useState(false)
  const [pwSuccess, setPwSuccess] = useState('')

  useEffect(() => {
    setIsTwoFAEnabled(!!user?.two_fa_enabled)
  }, [user?.two_fa_enabled])

  const qrImageUrl = useMemo(() => {
    if (!twoFAOtpauth) return ''
    const data = encodeURIComponent(twoFAOtpauth)
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${data}`
  }, [twoFAOtpauth])

  // Debugging helper: log when otpauth or qr URL changes so you can inspect in console
  useEffect(() => {
    if (twoFAOtpauth) console.debug('twoFAOtpauth:', twoFAOtpauth)
    if (qrImageUrl) console.debug('qrImageUrl:', qrImageUrl)
  }, [twoFAOtpauth, qrImageUrl])

  const copySecret = async () => {
    if (!twoFASecret) return
    try {
      await navigator.clipboard.writeText(twoFASecret)
      alert('Secret copied to clipboard')
    } catch (e) {
      console.error('Copy failed', e)
    }
  }

  const copyOtpauth = async () => {
    if (!twoFAOtpauth) return
    try {
      await navigator.clipboard.writeText(twoFAOtpauth)
      alert('otpauth_url copied to clipboard')
    } catch (e) {
      console.error('Copy failed', e)
    }
  }

  const startTwoFASetup = async () => {
    setTwoFAError('')
    setTwoFALoading(true)
    try {
      const token = localStorage.getItem('authToken')
      const resp = await fetch('/api/auth/2fa/setup', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      })
      if (!resp.ok) {
        throw new Error('Failed to start 2FA setup')
      }
      const data = await resp.json()
      setTwoFASecret(data.secret || '')
      setTwoFAOtpauth(data.qr_code_url || '')
      setIsSettingUp2FA(true)
    } catch (e: any) {
      setTwoFAError(e?.message || 'Error starting 2FA setup')
    } finally {
      setTwoFALoading(false)
    }
  }

  const confirmEnableTwoFA = async () => {
    setTwoFAError('')
    setTwoFALoading(true)
    try {
      const token = localStorage.getItem('authToken')
      const resp = await fetch('/api/auth/2fa/confirm', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code: twoFAOtpCode }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err?.error || 'Enable 2FA failed')
      }
      setIsTwoFAEnabled(true)
      setIsSettingUp2FA(false)
      setTwoFASecret('')
      setTwoFAOtpauth('')
      setTwoFAOtpCode('')
      alert('Two-factor authentication enabled')
    } catch (e: any) {
      setTwoFAError(e?.message || 'Error enabling 2FA')
    } finally {
      setTwoFALoading(false)
    }
  }

  const changePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setPwError('')
    setPwSuccess('')
    if (!currentPassword || !newPassword || !confirmNewPassword) {
      setPwError('Please fill all password fields')
      return
    }
    if (newPassword !== confirmNewPassword) {
      setPwError('New passwords do not match')
      return
    }
    setPwLoading(true)
    try {
      const token = localStorage.getItem('authToken')
      const resp = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err?.error || 'Change password failed')
      }
      setPwSuccess('Password updated successfully')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmNewPassword('')
    } catch (e: any) {
      setPwError(e?.message || 'Error updating password')
    } finally {
      setPwLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-3xl mx-auto px-4 py-8">
        <button onClick={() => navigate(-1)} className="mb-4 flex items-center gap-2 text-gray-300 hover:text-white">← Back</button>
        <h2 className="text-2xl font-bold mb-6 text-white">Account Settings</h2>

        <section className="bg-gray-800 p-6 rounded-lg border border-gray-700 mb-8">
          <h3 className="text-lg font-semibold text-white mb-4">Two-Factor Authentication (2FA)</h3>
          <p className="text-gray-300 mb-4">
            Status: {isTwoFAEnabled ? (<span className="text-green-400">Enabled</span>) : (<span className="text-red-400">Disabled</span>)}
          </p>

          {!isTwoFAEnabled && !isSettingUp2FA && (
            <button
              onClick={startTwoFASetup}
              disabled={twoFALoading}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium px-4 py-2 rounded"
            >
              {twoFALoading ? 'Preparing…' : 'Enable 2FA'}
            </button>
          )}

          {!isTwoFAEnabled && isSettingUp2FA && (
            <div>
              <p className="text-gray-400 mb-4">Scan the QR code below with your authenticator app (recommended), or copy the manual secret and add it to your app.</p>
              {qrImageUrl && (
                <div className="mb-4 text-center">
                  <img crossOrigin="anonymous" src={qrImageUrl} alt="2FA QR code to scan with an authenticator app" className="w-48 h-48 border border-gray-700 rounded mb-2 mx-auto" />
                  <div className="flex items-center justify-center gap-3 mb-2">
                    <a href={qrImageUrl} target="_blank" rel="noreferrer" className="text-sm text-blue-400 hover:underline">Open QR in new tab</a>
                    <button onClick={copyOtpauth} className="text-sm text-gray-300 bg-gray-700 px-2 py-1 rounded hover:bg-gray-600">Copy otpauth_url</button>
                  </div>
                  <p className="text-xs text-gray-400">If your app can't scan the code, use the manual secret shown below.</p>
                  <details className="mt-2 text-left text-xs text-gray-400">
                    <summary className="cursor-pointer text-gray-300">Show otpauth_url (for debugging)</summary>
                    <pre className="whitespace-pre-wrap break-words bg-gray-900 border border-gray-700 p-2 rounded mt-2 text-xs">{twoFAOtpauth}</pre>
                  </details>
                </div>
              )}

              {twoFASecret && (
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-1">Manual secret</label>
                  <div className="flex items-center gap-2">
                    <input
                      readOnly
                      value={twoFASecret}
                      className="flex-1 px-4 py-2 bg-gray-900 text-gray-200 text-sm rounded border border-gray-700 focus:outline-none"
                      aria-label="Manual 2FA secret"
                    />
                    <button onClick={copySecret} title="Copy secret" className="h-10 w-10 flex items-center justify-center bg-gray-700 hover:bg-gray-600 rounded">
                      <Clipboard size={16} />
                    </button>
                    <button onClick={startTwoFASetup} title="Regenerate secret and QR code" className="h-10 w-10 flex items-center justify-center bg-gray-700 hover:bg-gray-600 rounded">
                      <RefreshCw size={16} />
                    </button>
                  </div>
                </div>
              )}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-300 mb-2">Enter the 6-digit code from your authenticator app to confirm and enable 2FA</label>
                <input
                  type="text"
                  value={twoFAOtpCode}
                  onChange={(e) => setTwoFAOtpCode(e.target.value)}
                  placeholder="000000"
                  maxLength={6}
                  className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>
              {twoFAError && (
                <div className="bg-red-500/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-3 text-sm">{twoFAError}</div>
              )}
              <button
                onClick={confirmEnableTwoFA}
                disabled={twoFALoading || twoFAOtpCode.length < 6}
                className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white font-medium px-4 py-2 rounded"
              >
                {twoFALoading ? 'Enabling…' : 'Confirm & Enable'}
              </button>
            </div>
          )}
        </section>

        <section className="bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">Change Password</h3>
          <form onSubmit={changePassword} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
              <input
                type="password"
                value={confirmNewPassword}
                onChange={(e) => setConfirmNewPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>
            {pwError && (
              <div className="bg-red-500/20 border border-red-500 text-red-300 px-4 py-3 rounded text-sm">{pwError}</div>
            )}
            {pwSuccess && (
              <div className="bg-green-500/20 border border-green-500 text-green-300 px-4 py-3 rounded text-sm">{pwSuccess}</div>
            )}
            <button
              type="submit"
              disabled={pwLoading}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium px-4 py-2 rounded"
            >
              {pwLoading ? 'Updating…' : 'Change Password'}
            </button>
          </form>
        </section>
      </div>
    </div>
  )
}

export default Settings


