import { useState, useEffect } from 'react';

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

interface RulesListProps {
  rules: WAFRule[];
  onEdit: (rule: WAFRule) => void;
  onDelete: (id: string) => void;
  onToggle: (id: string) => void;
  onViewDetails: (rule: WAFRule) => void;
}

export default function RulesList({
  rules,
  onEdit,
  onDelete,
  onToggle,
  onViewDetails,
}: RulesListProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('all');
  const [modeFilter, setModeFilter] = useState('all');
  const [filteredRules, setFilteredRules] = useState<WAFRule[]>(rules);

  useEffect(() => {
    let filtered = [...rules];

    // Ricerca per nome e descrizione
    if (searchTerm) {
      filtered = filtered.filter(
        rule =>
          rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          rule.description.toLowerCase().includes(searchTerm.toLowerCase())
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

  const threatTypes = Array.from(new Set(rules.map(r => r.threatType)));

  return (
    <div className="space-y-6">
      {/* Filters & Search */}
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
              <option value="detect">🔍 Rileva</option>
              <option value="block">🚫 Blocca</option>
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

      {/* Rules Table */}
      {filteredRules.length > 0 && (
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
                        className={`px-3 py-1 rounded text-xs font-medium ${
                          rule.mode === 'block'
                            ? 'bg-red-500/20 text-red-300'
                            : 'bg-yellow-500/20 text-yellow-300'
                        }`}
                      >
                        {rule.mode === 'block' ? '🚫 Blocca' : '🔍 Rileva'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <button
                        onClick={() => onToggle(rule.id)}
                        className={`px-3 py-1 rounded text-xs font-medium transition ${
                          rule.enabled
                            ? 'bg-green-500/20 text-green-300 hover:bg-green-500/30'
                            : 'bg-gray-600/50 text-gray-400 hover:bg-gray-600'
                        }`}
                      >
                        {rule.enabled ? '✓ Attiva' : '✕ Disattiva'}
                      </button>
                    </td>
                    <td className="py-3 px-4 text-gray-400 text-xs">
                      {new Date(rule.createdAt).toLocaleDateString('it-IT')}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex justify-center gap-2">
                        <button
                          onClick={() => onViewDetails(rule)}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                        >
                          📋 Dettagli
                        </button>
                        <button
                          onClick={() => onEdit(rule)}
                          className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition"
                        >
                          ✏️ Modifica
                        </button>
                        <button
                          onClick={() => onDelete(rule.id)}
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
    </div>
  );
}