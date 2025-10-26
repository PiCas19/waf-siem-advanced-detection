import React, { useState } from 'react';
import { WAFRule } from '../../types/waf';

interface AddRuleProps {
  onRuleAdded: (rule: WAFRule) => void;
  onCancel: () => void;
  allRules: WAFRule[];
}

export default function AddRule({ onRuleAdded, onCancel, allRules }: AddRuleProps) {
  const [formData, setFormData] = useState({
    name: '',
    pattern: '',
    description: '',
    threatType: 'SQL Injection',
    mode: 'block' as 'block' | 'detect',
  });

  const threatTypes = Array.from(new Set(allRules.map(r => r.threatType)));
  const uniqueThreatTypes = ['SQL Injection', 'XSS', 'Command Injection', 'Directory Traversal', ...threatTypes];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name || !formData.pattern) {
      alert('Nome e Pattern sono obbligatori');
      return;
    }

    const token = localStorage.getItem('authToken');

    try {
      const response = await fetch('/api/rules', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        const data = await response.json();
        onRuleAdded(data.rule);
        alert('Regola creata con successo');
        setFormData({
          name: '',
          pattern: '',
          description: '',
          threatType: 'SQL Injection',
          mode: 'block',
        });
      } else {
        alert('Errore nella creazione della regola');
      }
    } catch (error) {
      console.error('Error creating rule:', error);
      alert('Errore nel salvataggio della regola');
    }
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
      <h2 className="text-xl font-semibold text-white mb-6">Crea Nuova Regola</h2>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Nome */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Nome Regola</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="es. SQL Injection Prevention"
            className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
        </div>

        {/* Pattern */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Pattern (Regex)
          </label>
          <textarea
            value={formData.pattern}
            onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
            placeholder="es. SELECT|INSERT|UPDATE|DELETE|DROP"
            rows={3}
            className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none font-mono text-sm"
          />
          <p className="text-xs text-gray-400 mt-1">
            Inserisci un'espressione regolare per matchare i pattern di attacco
          </p>
        </div>

        {/* Descrizione */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Descrizione</label>
          <textarea
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            placeholder="Descrizione della regola..."
            rows={2}
            className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Tipo di Minaccia */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Tipo di Minaccia
            </label>
            <select
              value={formData.threatType}
              onChange={(e) => setFormData({ ...formData, threatType: e.target.value })}
              className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              {uniqueThreatTypes.map(type => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>

          {/* Modalità */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Modalità</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="mode"
                  value="detect"
                  checked={formData.mode === 'detect'}
                  onChange={(e) => setFormData({ ...formData, mode: e.target.value as 'detect' | 'block' })}
                  className="w-4 h-4"
                />
                <span className="text-gray-300">🔍 Rileva solo</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="mode"
                  value="block"
                  checked={formData.mode === 'block'}
                  onChange={(e) => setFormData({ ...formData, mode: e.target.value as 'detect' | 'block' })}
                  className="w-4 h-4"
                />
                <span className="text-gray-300">🚫 Blocca</span>
              </label>
            </div>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex gap-4 pt-4">
          <button
            type="submit"
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium transition"
          >
            Crea Regola
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition"
          >
            Annulla
          </button>
        </div>
      </form>
    </div>
  );
}