import React, { useEffect, useState, useMemo } from 'react'
import axios from 'axios'
import { Trash2, Edit2 } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { useSnackbar } from '@/contexts/SnackbarContext'

interface User {
  id: number
  email: string
  name: string
  role: string
  active: boolean
  two_fa_enabled: boolean
  created_at: string
  updated_at: string
}

type SortField = 'email' | 'name' | 'role' | 'created_at'
type SortOrder = 'asc' | 'desc'

const Users: React.FC = () => {
  const { token, user: currentUser, isLoading: authLoading } = useAuth()
  const { showToast } = useSnackbar()
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Form state
  const [showForm, setShowForm] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState('user')
  const [formLoading, setFormLoading] = useState(false)

  // Edit modal state
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editName, setEditName] = useState('')
  const [editRole, setEditRole] = useState('')
  const [editLoading, setEditLoading] = useState(false)

  // Delete confirmation state
  const [deleteUserId, setDeleteUserId] = useState<number | null>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [deleteLoading, setDeleteLoading] = useState(false)

  // Table state
  const [searchTerm, setSearchTerm] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [sortField, setSortField] = useState<SortField>('created_at')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')
  const [currentPage, setCurrentPage] = useState(1)
  const itemsPerPage = 10

  // Load users when auth is ready
  useEffect(() => {
    if (!authLoading && token) {
      loadUsers()
    }
  }, [authLoading, token])

  const loadUsers = async () => {
    setLoading(true)
    setError('')
    try {
      const resp = await axios.get('/api/admin/users', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      setUsers(resp.data.users || [])
    } catch (e: any) {
      setError(e.response?.data?.error || 'Failed to load users')
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  // Filter and sort logic
  const filteredUsers = useMemo(() => {
    let filtered = users.filter(u => {
      const matchesSearch =
        u.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.name.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesRole = roleFilter === 'all' || u.role === roleFilter
      return matchesSearch && matchesRole
    })

    // Sort
    filtered.sort((a, b) => {
      let aVal: any = a[sortField]
      let bVal: any = b[sortField]

      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase()
        bVal = bVal.toLowerCase()
      }

      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1
      return 0
    })

    return filtered
  }, [users, searchTerm, roleFilter, sortField, sortOrder])

  // Pagination
  const totalPages = Math.ceil(filteredUsers.length / itemsPerPage)
  const paginatedUsers = filteredUsers.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('asc')
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormLoading(true)
    try {
      await axios.post('/api/admin/users', { email, name, role }, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      showToast('User created successfully!', 'success')
      setEmail('')
      setName('')
      setRole('user')
      setShowForm(false)
      // Reset pagination to first page
      setCurrentPage(1)
      // Reload list
      await loadUsers()
    } catch (err: any) {
      showToast(err.response?.data?.error || 'Creation failed', 'error')
    } finally {
      setFormLoading(false)
    }
  }

  const handleDeleteUser = async () => {
    if (!deleteUserId) return
    setDeleteLoading(true)
    try {
      await axios.delete(`/api/admin/users/${deleteUserId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      showToast('User deleted successfully!', 'success')
      setShowDeleteConfirm(false)
      setDeleteUserId(null)
      await loadUsers()
    } catch (err: any) {
      showToast(err.response?.data?.error || 'Failed to delete user', 'error')
    } finally {
      setDeleteLoading(false)
    }
  }

  const handleEditUser = (user: User) => {
    setEditingUser(user)
    setEditName(user.name)
    setEditRole(user.role)
    setShowEditModal(true)
  }

  const handleSaveEdit = async () => {
    if (!editingUser) return
    setEditLoading(true)
    try {
      await axios.put(`/api/admin/users/${editingUser.id}`, { name: editName, role: editRole }, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      showToast('User updated successfully!', 'success')
      setShowEditModal(false)
      setEditingUser(null)
      await loadUsers()
    } catch (err: any) {
      showToast(err.response?.data?.error || 'Failed to update user', 'error')
    } finally {
      setEditLoading(false)
    }
  }

  const getRoleColor = (role: string) => {
    const colors: Record<string, string> = {
      admin: 'bg-red-900 text-red-100',
      operator: 'bg-blue-900 text-blue-100',
      analyst: 'bg-green-900 text-green-100',
      user: 'bg-gray-700 text-gray-100'
    }
    return colors[role] || 'bg-gray-700 text-gray-100'
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <span className="text-gray-500 ml-1">⇅</span>
    return <span className="text-white ml-1">{sortOrder === 'asc' ? '↑' : '↓'}</span>
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-white">User Management</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-white font-medium transition"
        >
          {showForm ? 'Cancel' : '+ Add User'}
        </button>
      </div>

      {error && <div className="bg-red-900 text-red-100 p-3 rounded mb-4">{error}</div>}

      {/* Create User Form */}
      {showForm && (
        <form onSubmit={handleCreate} className="bg-gray-800 p-6 rounded mb-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">Create New User</h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm text-gray-300 mb-2">Email</label>
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                type="email"
                required
                className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
                placeholder="user@example.com"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-2">Full Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                type="text"
                required
                className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
                placeholder="John Doe"
              />
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-sm text-gray-300 mb-2">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
            >
              <option value="admin">Admin</option>
              <option value="operator">Operator</option>
              <option value="analyst">Analyst</option>
              <option value="user">User</option>
            </select>
          </div>

          <div className="flex gap-2">
            <button
              type="submit"
              disabled={formLoading}
              className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-4 py-2 rounded text-white font-medium transition"
            >
              {formLoading ? 'Creating…' : 'Create User'}
            </button>
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded text-white font-medium transition"
            >
              Close
            </button>
          </div>
        </form>
      )}

      {/* Filters and Search */}
      <div className="bg-gray-800 p-4 rounded mb-6 border border-gray-700">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-300 mb-2">Search</label>
            <input
              type="text"
              placeholder="Search by email or name..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value)
                setCurrentPage(1)
              }}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-300 mb-2">Filter by Role</label>
            <select
              value={roleFilter}
              onChange={(e) => {
                setRoleFilter(e.target.value)
                setCurrentPage(1)
              }}
              className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
            >
              <option value="all">All Roles</option>
              <option value="admin">Admin</option>
              <option value="operator">Operator</option>
              <option value="analyst">Analyst</option>
              <option value="user">User</option>
            </select>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-gray-400">Loading users...</div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-gray-400">No users found</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-900 border-b border-gray-700">
                  <tr>
                    <th
                      onClick={() => handleSort('email')}
                      className="px-6 py-3 text-left text-sm font-semibold text-gray-300 cursor-pointer hover:text-white transition"
                    >
                      Email <SortIcon field="email" />
                    </th>
                    <th
                      onClick={() => handleSort('name')}
                      className="px-6 py-3 text-left text-sm font-semibold text-gray-300 cursor-pointer hover:text-white transition"
                    >
                      Name <SortIcon field="name" />
                    </th>
                    <th
                      onClick={() => handleSort('role')}
                      className="px-6 py-3 text-left text-sm font-semibold text-gray-300 cursor-pointer hover:text-white transition"
                    >
                      Role <SortIcon field="role" />
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-300">Status</th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-300">2FA</th>
                    <th
                      onClick={() => handleSort('created_at')}
                      className="px-6 py-3 text-left text-sm font-semibold text-gray-300 cursor-pointer hover:text-white transition"
                    >
                      Created <SortIcon field="created_at" />
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedUsers.map((user) => (
                    <tr key={user.id} className="border-b border-gray-700 hover:bg-gray-750 transition">
                      <td className="px-6 py-4 text-sm text-gray-300">{user.email}</td>
                      <td className="px-6 py-4 text-sm text-gray-300">{user.name}</td>
                      <td className="px-6 py-4 text-sm">
                        <span className={`px-3 py-1 rounded text-xs font-medium ${getRoleColor(user.role)}`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span className={`text-xs font-medium ${user.active ? 'text-green-400' : 'text-red-400'}`}>
                          {user.active ? '✓ Active' : '✗ Inactive'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span className={`text-xs font-medium ${user.two_fa_enabled ? 'text-green-400' : 'text-gray-400'}`}>
                          {user.two_fa_enabled ? '✓ Enabled' : '✗ Disabled'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-sm flex gap-2">
                        <button
                          onClick={() => handleEditUser(user)}
                          disabled={!!(currentUser && user.id === currentUser.id)}
                          className={`p-2 rounded transition ${
                            currentUser && user.id === currentUser.id
                              ? 'bg-gray-600 text-gray-400 cursor-not-allowed opacity-50'
                              : 'bg-blue-600 hover:bg-blue-700 text-white'
                          }`}
                          title={currentUser && user.id === currentUser.id ? 'Cannot edit your own account' : 'Edit user'}
                        >
                          <Edit2 size={16} />
                        </button>
                        <button
                          onClick={() => {
                            setDeleteUserId(user.id)
                            setShowDeleteConfirm(true)
                          }}
                          disabled={!!(currentUser && user.id === currentUser.id)}
                          className={`p-2 rounded transition ${
                            currentUser && user.id === currentUser.id
                              ? 'bg-gray-600 text-gray-400 cursor-not-allowed opacity-50'
                              : 'bg-red-600 hover:bg-red-700 text-white'
                          }`}
                          title={currentUser && user.id === currentUser.id ? 'Cannot delete your own account' : 'Delete user'}
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="bg-gray-900 px-6 py-4 border-t border-gray-700 flex items-center justify-between">
              <div className="text-sm text-gray-400">
                Showing {paginatedUsers.length === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, filteredUsers.length)} of {filteredUsers.length} users
              </div>
              <div className="flex gap-2">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  className="px-3 py-1 rounded text-sm border border-gray-600 text-gray-300 hover:text-white disabled:opacity-50 transition"
                >
                  Previous
                </button>
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                    <button
                      key={page}
                      onClick={() => setCurrentPage(page)}
                      className={`px-3 py-1 rounded text-sm transition ${
                        currentPage === page
                          ? 'bg-blue-600 text-white'
                          : 'border border-gray-600 text-gray-300 hover:text-white'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                </div>
                <button
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                  className="px-3 py-1 rounded text-sm border border-gray-600 text-gray-300 hover:text-white disabled:opacity-50 transition"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg max-w-sm border border-gray-700">
            <h2 className="text-lg font-bold text-white mb-4">Confirm Delete</h2>
            <p className="text-gray-300 mb-6">Are you sure you want to delete this user? This action cannot be undone.</p>
            <div className="flex gap-3">
              <button
                onClick={handleDeleteUser}
                disabled={deleteLoading}
                className="flex-1 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white font-medium py-2 px-4 rounded transition"
              >
                {deleteLoading ? 'Deleting...' : 'Delete'}
              </button>
              <button
                onClick={() => {
                  setShowDeleteConfirm(false)
                  setDeleteUserId(null)
                }}
                className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded transition"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && editingUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg max-w-md border border-gray-700">
            <h2 className="text-lg font-bold text-white mb-4">Edit User</h2>
            <div className="space-y-4 mb-6">
              <div>
                <label className="block text-sm text-gray-300 mb-2">Name</label>
                <input
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-300 mb-2">Role</label>
                <select
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 outline-none"
                >
                  <option value="admin">Admin</option>
                  <option value="operator">Operator</option>
                  <option value="analyst">Analyst</option>
                  <option value="user">User</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleSaveEdit}
                disabled={editLoading}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium py-2 px-4 rounded transition"
              >
                {editLoading ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={() => {
                  setShowEditModal(false)
                  setEditingUser(null)
                }}
                className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded transition"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      </div>
    </div>
  )
}

export default Users
