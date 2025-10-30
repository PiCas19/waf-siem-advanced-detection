import React from 'react'
import { Link } from 'react-router-dom'

const Register: React.FC = () => {
  // Public self-registration is disabled. Admins should create new users
  // via the admin UI. This page informs the user and provides a login link.
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md text-center">
        <h1 className="text-2xl font-bold text-white mb-4">Registration Disabled</h1>
        <p className="text-gray-300 mb-4">Account creation is restricted to administrators. If you need an account, please contact your administrator.</p>
        <Link to="/login" className="inline-block bg-blue-600 px-4 py-2 rounded text-white">Go to Login</Link>
      </div>
    </div>
  )
}

export default Register
