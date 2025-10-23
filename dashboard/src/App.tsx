import React from 'react';

function App() {
  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <h1 className="text-2xl font-bold">WAF Dashboard</h1>
        </div>
      </header>
      
      <main className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gray-800 p-6 rounded-lg">
            <h2 className="text-lg font-semibold mb-2">Threats Detected</h2>
            <p className="text-3xl font-bold text-red-500">0</p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg">
            <h2 className="text-lg font-semibold mb-2">Requests Blocked</h2>
            <p className="text-3xl font-bold text-yellow-500">0</p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg">
            <h2 className="text-lg font-semibold mb-2">Total Requests</h2>
            <p className="text-3xl font-bold text-green-500">0</p>
          </div>
        </div>
        
        <div className="mt-8 bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Recent Alerts</h2>
          <p className="text-gray-400">No alerts yet. Dashboard is ready for integration.</p>
        </div>
      </main>
    </div>
  );
}

export default App;