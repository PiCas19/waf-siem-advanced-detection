import { useState, useEffect } from 'react';
import { WAFRule, getCreatedDate } from '../../types/waf';

interface RulesListProps {
  defaultRules?: WAFRule[];
  customRules?: WAFRule[];
  rules?: WAFRule[];
  onEdit: (rule: WAFRule) => void;
  onDelete: (id: string) => void;
  onToggle: (id: string) => void;
  onViewDetails: (rule: WAFRule) => void;
}

export default function RulesList({
  defaultRules = [],
  customRules = [],
  rules = [],
  onEdit,
  onDelete,
  onToggle,
  onViewDetails,
}: RulesListProps) {
  // Se viene passato 'rules' per compatibilità, usalo
  const allCustomRules = customRules.length > 0 ? customRules : rules;
  const allDefaultRules = defaultRules;

  const [searchTerm, setSearchTerm] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('all');
  const [modeFilter, setModeFilter] = useState('all');
  const [filteredDefaultRules, setFilteredDefaultRules] = useState<WAFRule[]>([]);
  const [filteredCustomRules, setFilteredCustomRules] = useState<WAFRule[]>([]);

  useEffect(() => {
    // Filtra default rules
    let filteredDefaults = [...allDefaultRules];

    if (searchTerm) {
      filteredDefaults = filteredDefaults.filter(
        rule =>
          rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          rule.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (threatTypeFilter !== 'all') {
      filteredDefaults = filteredDefaults.filter(
        rule => (rule.type || rule.threatType) === threatTypeFilter
      );
    }

    setFilteredDefaultRules(filteredDefaults);

    // Filtra custom rules
    let filteredCustom = [...allCustomRules];

    if (searchTerm) {
      filteredCustom = filteredCustom.filter(
        rule =>
          rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          rule.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (threatTypeFilter !== 'all') {
      filteredCustom = filteredCustom.filter(
        rule => (rule.type || rule.threatType) === threatTypeFilter
      );
    }

    if (modeFilter !== 'all') {
      filteredCustom = filteredCustom.filter(rule => (rule.action || rule.mode) === modeFilter);
    }

    setFilteredCustomRules(filteredCustom);
  }, [allCustomRules, allDefaultRules, searchTerm, threatTypeFilter, modeFilter]);

  const threatTypes = Array.from(
    new Set(
      [...allDefaultRules, ...allCustomRules].map(r => r.type || r.threatType || '')
    )
  ).filter(t => t !== '');

  return (
    <div className="space-y-6">
      {/* Filters & Search */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Search</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by name..."
              className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </div>

          {/* Filter by Type */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Threat Type</label>
            <select
              value={threatTypeFilter}
              onChange={(e) => setThreatTypeFilter(e.target.value)}
              className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All types</option>
              {threatTypes.map(type => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>

          {/* Filter by Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Mode</label>
            <select
              value={modeFilter}
              onChange={(e) => setModeFilter(e.target.value)}
              className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All modes</option>
              <option value="detect">Detect</option>
              <option value="block">Block</option>
            </select>
          </div>

          {/* Summary */}
          <div className="flex items-end">
            <div className="text-sm text-gray-400">
              {filteredDefaultRules.length + filteredCustomRules.length} rule{filteredDefaultRules.length + filteredCustomRules.length !== 1 ? 's' : ''} (
              {filteredDefaultRules.length} default + {filteredCustomRules.length} custom)
            </div>
          </div>
        </div>
      </div>

      {/* Default Rules Table */}
      {filteredDefaultRules.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-bold text-white">
            Default Rules (Built-in)
          </h2>
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-700">
                  <tr>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Name</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Threat Type</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Severity</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Status</th>
                    <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDefaultRules.map((rule) => (
                    <tr key={rule.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                      <td className="py-3 px-4 text-gray-300 font-medium">{rule.name}</td>
                      <td className="py-3 px-4 text-gray-400">{rule.type}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-3 py-1 rounded text-xs font-medium ${
                            rule.severity === 'CRITICAL'
                              ? 'bg-red-500/20 text-red-300'
                              : rule.severity === 'HIGH'
                              ? 'bg-orange-500/20 text-orange-300'
                              : 'bg-yellow-500/20 text-yellow-300'
                          }`}
                        >
                          {rule.severity || 'N/A'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-3 py-1 bg-green-500/20 text-green-300 rounded text-xs font-medium">
                          Always Active
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex justify-center">
                          <button
                            onClick={() => onViewDetails(rule)}
                            className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                          >
                            Details
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Custom Rules Table */}
      {filteredCustomRules.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-bold text-white">
            Custom Rules
          </h2>
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-700">
                  <tr>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Name</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Threat Type</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Mode</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Status</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-medium">Created</th>
                    <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCustomRules.map((rule) => (
                    <tr key={rule.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                      <td className="py-3 px-4 text-gray-300 font-medium">{rule.name}</td>
                      <td className="py-3 px-4 text-gray-400">{rule.type || rule.threatType}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-3 py-1 rounded text-xs font-medium ${
                            rule.action === 'block' || rule.mode === 'block'
                              ? 'bg-red-500/20 text-red-300'
                              : 'bg-yellow-500/20 text-yellow-300'
                          }`}
                        >
                          {rule.action === 'block' || rule.mode === 'block' ? 'BLOCK' : 'DETECT'}
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
                          {rule.enabled ? 'ENABLED' : 'DISABLED'}
                        </button>
                      </td>
                      <td className="py-3 px-4 text-gray-400 text-xs">
                        {getCreatedDate(rule).split(' ')[0]}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex justify-center gap-2">
                          <button
                            onClick={() => onViewDetails(rule)}
                            className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                          >
                            Details
                          </button>
                          <button
                            onClick={() => onEdit(rule)}
                            className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => onDelete(rule.id)}
                            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {filteredDefaultRules.length === 0 && filteredCustomRules.length === 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
          <p className="text-gray-400">No rules found</p>
        </div>
      )}
    </div>
  );
}