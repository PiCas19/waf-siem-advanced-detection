import React, { useEffect, useState } from 'react'
import axios from 'axios'

interface User {
  id: number
  email: string
  name: string
  role: string
}

const Users: React.FC = () => {
  const [users, setUsers] = useState<User[]>([])
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState('user')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

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
    setLoading(true)
    try {
      const resp = await axios.post('/api/admin/users', { email, name, role })
      const info = resp.data
      setMessage(`User created. ${info.email || ''}`)
      setEmail('')
      setName('')
      setRole('user')
      // reload list
      try {
        const list = await axios.get('/api/admin/users')
        setUsers(list.data.users || [])
      } catch (_e) {
        // ignore
      }
    } catch (err: any) {
      setMessage(err.response?.data?.error || 'Creation failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <h2 className="text-xl font-semibold mb-4 text-white">User Management</h2>

      <form onSubmit={handleCreate} className="space-y-4 bg-gray-800 p-6 rounded mb-6">
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
            <option value="admin">Admin</option>
            <option value="manager">Manager</option>
            <option value="operator">Operator</option>
            <option value="auditor">Auditor</option>
            <option value="viewer">Viewer</option>
            <option value="user">User</option>
          </select>
        </div>

        <div>
          <button disabled={loading} className="bg-blue-600 px-4 py-2 rounded text-white">{loading ? 'Creating…' : 'Create user'}</button>
        </div>
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
