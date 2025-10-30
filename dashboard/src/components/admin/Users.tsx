import React, { useState } from 'react'
import axios from 'axios'

const Users: React.FC = () => {
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState('user')
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setResult(null)
    setLoading(true)
    try {
      const resp = await axios.post('/api/admin/users', { email, name, role })
      setResult(resp.data)
      setEmail('')
      setName('')
      setRole('user')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <h2 className="text-xl font-bold mb-4">Admin: Create User</h2>
      {error && <div className="text-red-400 mb-3">{error}</div>}
      {result && (
        <div className="bg-gray-800 p-3 rounded mb-4">
          <pre className="text-sm text-gray-300">{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}

      <form onSubmit={submit} className="space-y-4 bg-gray-800 p-6 rounded">
        <div>
          <label className="block text-sm text-gray-300 mb-1">Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required className="w-full px-3 py-2 bg-gray-700 text-white rounded" />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Full name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} type="text" required className="w-full px-3 py-2 bg-gray-700 text-white rounded" />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Role</label>
          <select value={role} onChange={(e) => setRole(e.target.value)} className="w-full px-3 py-2 bg-gray-700 text-white rounded">
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </div>

        <div>
          <button disabled={loading} className="bg-blue-600 px-4 py-2 rounded text-white">{loading ? 'Creating…' : 'Create user'}</button>
        </div>
      </form>
    </div>
  )
}

export default Users
import React, { useEffect, useState } from 'react'
import axios from 'axios'

const Users: React.FC = () => {
  const [users, setUsers] = useState<any[]>([])
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState('user')
  const [message, setMessage] = useState('')

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await axios.get('/api/admin/users')
        setUsers(resp.data.users || [])
      } catch (e) {
        console.error(e)
      }
    }
    load()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setMessage('')
    try {
      const resp = await axios.post('/api/admin/users', { email, name, role })
      setMessage(`User created. Reset link: ${resp.data.reset_link} Temp password: ${resp.data.temp_password}`)
      setEmail('')
      setName('')
      setRole('user')
    } catch (err: any) {
      setMessage(err.response?.data?.error || 'Creation failed')
    }
  }

  return (
    <div className="p-6">
      <h2 className="text-xl font-semibold mb-4 text-white">User Management</h2>
      <form onSubmit={handleCreate} className="space-y-3 mb-6">
        <div>
          <label className="block text-sm text-gray-300 mb-1">Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} className="px-3 py-2 bg-gray-700 text-white rounded w-full" />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Full name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} className="px-3 py-2 bg-gray-700 text-white rounded w-full" />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Role</label>
          <select value={role} onChange={(e) => setRole(e.target.value)} className="px-3 py-2 bg-gray-700 text-white rounded">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <button className="bg-blue-600 px-4 py-2 rounded text-white">Create user</button>
      </form>

      {message && <div className="text-sm text-gray-300 mb-4">{message}</div>}

      <h3 className="text-lg font-medium text-white mb-2">Existing users</h3>
      <ul className="space-y-2">
        {users.map((u) => (
          <li key={u.id} className="text-gray-300">{u.email} — {u.name} — {u.role}</li>
        ))}
      </ul>
    </div>
  )
}

export default Users
