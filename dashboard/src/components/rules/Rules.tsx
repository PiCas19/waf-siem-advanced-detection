import React, { useState, useEffect } from 'react';
import { Search, Shield } from 'lucide-react';
import { useToast } from '@/contexts/SnackbarContext';

interface WAFRule {
  id: string;
  name: string;
  pattern: string;
  description: string;
  threatType: string;
  mode: 'block' | 'detect';
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

const Rules: React.FC = () => {
  const { showToast } = useToast();
  const [rules, setRules] = useState<WAFRule[]>([]);
  const [filteredRules, setFilteredRules] = useState<WAFRule[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('all');
  const [modeFilter, setModeFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState<WAFRule | null>(null);
  const [selectedRule, setSelectedRule] = useState<WAFRule | null>(null);
  const [showDetails, setShowDetails] = useState(false);

  const [formData, setFormData] = useState({
    name: '',
    pattern: '',
    description: '',
    threatType: 'SQL Injection',
    mode: 'block' as 'block' | 'detect',
  });

  // Carica regole dal backend
  useEffect(() => {
    loadRules();
  }, []);

  // Applica filtri e ricerca
  useEffect(() => {
    let filtered = [...rules];

    // Ricerca per nome e descrizione
    if (searchTerm) {
      filtered = filtered.filter(
        rule =>
          (rule.name?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
          (rule.description?.toLowerCase() || '').includes(searchTerm.toLowerCase())
      );
    }

    // Filtra per tipo di minaccia
    if (threatTypeFilter !== 'all') {
      filtered = filtered.filter(rule => rule.threatType === threatTypeFilter);
    }

    // Filtra per modalità
    if (modeFilter !== 'all') {
      filtered = filtered.filter(rule => rule.mode === modeFilter);
    }

    setFilteredRules(filtered);
  }, [rules, searchTerm, threatTypeFilter, modeFilter]);

  const loadRules = async () => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/api/rules', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await response.json();
      setRules(data.rules || []);
    } catch (error) {
      console.error('Failed to load rules:', error);
    }
  };

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name || !formData.pattern) {
      showToast('Nome e Pattern sono obbligatori', 'info', 4000);
      return;
    }

    const token = localStorage.getItem('authToken');

    try {
      if (editingRule) {
        // Modifica regola esistente
        const response = await fetch(`/api/rules/${editingRule.id}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(formData),
        });

        if (response.ok) {
          const data = await response.json();
          setRules(
            rules.map(r =>
              r.id === editingRule.id ? data.rule : r
            )
          );
          setEditingRule(null);
          showToast('Regola aggiornata con successo', 'success', 4000);
        }
      } else {
        // Crea nuova regola
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
          setRules([...rules, data.rule]);
          showToast('Regola creata con successo', 'success', 4000);
        }
      }

      // Resetta form
      setFormData({
        name: '',
        pattern: '',
        description: '',
        threatType: 'SQL Injection',
        mode: 'block',
      });
      setShowForm(false);
    } catch (error) {
      showToast('Errore nel salvataggio della regola', 'error', 4000);
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (confirm('Sei sicuro di voler eliminare questa regola?')) {
      const token = localStorage.getItem('authToken');

      try {
        const ruleToDelete = rules.find(r => r.id === id);

        const response = await fetch(`/api/rules/${id}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          setRules(rules.filter(r => r.id !== id));
          setShowDetails(false);
          showToast('Regola eliminata con successo', 'success', 4000);

          // Auto-unblock threat if this is a manual block rule
          if (ruleToDelete && ruleToDelete.name.startsWith('Manual Block: ')) {
            const threatDescription = ruleToDelete.name.replace('Manual Block: ', '');

            try {
              // Find the IP of the threat - we need to fetch logs to match IP with threat
              const logsResponse = await fetch('/api/logs', {
                headers: {
                  'Authorization': `Bearer ${token}`,
                },
              });

              if (logsResponse.ok) {
                const logsData = await logsResponse.json();
                const logs = logsData.security_logs || logsData.logs || [];

                // Find the threat matching this description
                const matchingThreat = logs.find((log: any) =>
                  log.description === threatDescription || log.threat_type === threatDescription
                );

                if (matchingThreat) {
                  // Unblock the threat
                  await fetch('/api/logs/threat-status', {
                    method: 'PUT',
                    headers: {
                      'Authorization': `Bearer ${token}`,
                      'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                      ip: matchingThreat.client_ip || matchingThreat.ip,
                      description: threatDescription,
                      blocked: false,
                      blocked_by: '',
                    }),
                  });
                }
              }
            } catch (error) {
              // Silently fail - rule was deleted successfully
            }
          }
        }
      } catch (error) {
        showToast('Errore nell\'eliminazione della regola', 'error', 4000);
      }
    }
  };

  const handleEditRule = (rule: WAFRule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      pattern: rule.pattern,
      description: rule.description,
      threatType: rule.threatType,
      mode: rule.mode,
    });
    setShowForm(true);
    setShowDetails(false);
  };

  const handleToggleRule = async (id: string) => {
    const token = localStorage.getItem('authToken');

    try {
      const response = await fetch(`/api/rules/${id}/toggle`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setRules(
          rules.map(r =>
            r.id === id
              ? {
                  ...r,
                  enabled: data.enabled,
                  updatedAt: new Date().toISOString(),
                }
              : r
          )
        );
      }
    } catch (error) {
      console.error('Error toggling rule:', error);
    }
  };

  const threatTypes = Array.from(new Set(rules.map(r => r.threatType)));
  const uniqueThreatTypes = ['SQL Injection', 'XSS', 'Command Injection', 'Directory Traversal', ...threatTypes];

  const handleCancel = () => {
    setShowForm(false);
    setEditingRule(null);
    setFormData({
      name: '',
      pattern: '',
      description: '',
      threatType: 'SQL Injection',
      mode: 'block',
    });
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">WAF Rules</h1>
          <p className="text-gray-400">Crea e gestisci le regole personalizzate del WAF</p>
        </div>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
          >
            + Add Rule
          </button>
        )}
      </div>

      {/* Form - Create/Edit Rule */}
      {showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h2 className="text-xl font-semibold text-white mb-6">
            {editingRule ? 'Modifica Regola' : 'Crea Nuova Regola'}
          </h2>

          <form onSubmit={handleAddRule} className="space-y-6">
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
                    <span className="text-gray-300 flex items-center gap-1">
                      <Search size={14} />
                      Rileva solo
                    </span>
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
                    <span className="text-gray-300 flex items-center gap-1">
                      <Shield size={14} />
                      Blocca
                    </span>
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
                {editingRule ? 'Salva Modifiche' : 'Crea Regola'}
              </button>
              <button
                type="button"
                onClick={handleCancel}
                className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition"
              >
                Annulla
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Filters & Search */}
      {!showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Ricerca */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Ricerca</label>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Cerca per nome..."
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
              />
            </div>

            {/* Filtra per Tipo */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Tipo Minaccia</label>
              <select
                value={threatTypeFilter}
                onChange={(e) => setThreatTypeFilter(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
              >
                <option value="all">Tutti i tipi</option>
                {threatTypes.map(type => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </div>

            {/* Filtra per Modalità */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Modalità</label>
              <select
                value={modeFilter}
                onChange={(e) => setModeFilter(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
              >
                <option value="all">Tutte le modalità</option>
                <option value="detect">Rileva</option>
                <option value="block">Blocca</option>
              </select>
            </div>

            {/* Stato */}
            <div className="flex items-end">
              <div className="text-sm text-gray-400">
                {filteredRules.length} regola{filteredRules.length !== 1 ? 'e' : ''}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Rules Table */}
      {!showForm && filteredRules.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700">
                <tr>
                  <th className="text-left py-3 px-4 text-gray-300 font-medium">Nome</th>
                  <th className="text-left py-3 px-4 text-gray-300 font-medium">Tipo Minaccia</th>
                  <th className="text-left py-3 px-4 text-gray-300 font-medium">Modalità</th>
                  <th className="text-left py-3 px-4 text-gray-300 font-medium">Stato</th>
                  <th className="text-left py-3 px-4 text-gray-300 font-medium">Creata</th>
                  <th className="text-center py-3 px-4 text-gray-300 font-medium">Azioni</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule) => (
                  <tr key={rule.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                    <td className="py-3 px-4 text-gray-300 font-medium">{rule.name}</td>
                    <td className="py-3 px-4 text-gray-400">{rule.threatType}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-3 py-1 rounded text-xs font-medium inline-flex items-center gap-1 ${
                          rule.mode === 'block'
                            ? 'bg-red-500/20 text-red-300'
                            : 'bg-yellow-500/20 text-yellow-300'
                        }`}
                      >
                        {rule.mode === 'block' ? (
                          <>
                            <Shield size={12} />
                            Blocca
                          </>
                        ) : (
                          <>
                            <Search size={12} />
                            Rileva
                          </>
                        )}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <button
                        onClick={() => handleToggleRule(rule.id)}
                        className={`px-3 py-1 rounded text-xs font-medium transition inline-flex items-center gap-1 ${
                          rule.enabled
                            ? 'bg-green-500/20 text-green-300 hover:bg-green-500/30'
                            : 'bg-gray-600/50 text-gray-400 hover:bg-gray-600'
                        }`}
                      >
                        {rule.enabled ? 'Attiva' : 'Disattiva'}
                      </button>
                    </td>
                    <td className="py-3 px-4 text-gray-400 text-xs">
                      {new Date(rule.createdAt).toLocaleDateString('it-IT')}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex justify-center gap-2">
                        <button
                          onClick={() => {
                            setSelectedRule(rule);
                            setShowDetails(true);
                          }}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                        >
                          📋 Dettagli
                        </button>
                        <button
                          onClick={() => handleEditRule(rule)}
                          className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition"
                        >
                          ✏️ Modifica
                        </button>
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                        >
                          🗑️ Elimina
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Rule Details Modal */}
      {showDetails && selectedRule && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full p-6 max-h-96 overflow-y-auto">
            <div className="flex justify-between items-start mb-6">
              <h2 className="text-2xl font-bold text-white">{selectedRule.name}</h2>
              <button
                onClick={() => setShowDetails(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-400">Descrizione</p>
                <p className="text-gray-300 mt-1">{selectedRule.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-400">Tipo di Minaccia</p>
                  <p className="text-gray-300 mt-1 font-medium">{selectedRule.threatType}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Modalità</p>
                  <p className="text-gray-300 mt-1 font-medium flex items-center gap-1">
                    {selectedRule.mode === 'block' ? (
                      <>
                        <Shield size={14} />
                        Blocca
                      </>
                    ) : (
                      <>
                        <Search size={14} />
                        Rileva
                      </>
                    )}
                  </p>
                </div>
              </div>

              <div>
                <p className="text-sm text-gray-400">Pattern (Regex)</p>
                <div className="bg-gray-700 p-3 rounded mt-1 font-mono text-sm text-gray-300 break-all">
                  {selectedRule.pattern}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-400">Creata</p>
                  <p className="text-gray-300 mt-1">
                    {new Date(selectedRule.createdAt).toLocaleString('it-IT')}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Ultimo Aggiornamento</p>
                  <p className="text-gray-300 mt-1">
                    {new Date(selectedRule.updatedAt).toLocaleString('it-IT')}
                  </p>
                </div>
              </div>

              <div>
                <p className="text-sm text-gray-400">Stato</p>
                <p className="text-gray-300 mt-1">
                  {selectedRule.enabled ? '✓ Attiva' : '✕ Disattiva'}
                </p>
              </div>
            </div>

            <div className="flex gap-4 mt-6 pt-6 border-t border-gray-700">
              <button
                onClick={() => {
                  handleEditRule(selectedRule);
                  setShowDetails(false);
                }}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium transition"
              >
                ✏️ Modifica
              </button>
              <button
                onClick={() => {
                  handleDeleteRule(selectedRule.id);
                }}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium transition"
              >
                🗑️ Elimina
              </button>
              <button
                onClick={() => setShowDetails(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition ml-auto"
              >
                Chiudi
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Rules;
