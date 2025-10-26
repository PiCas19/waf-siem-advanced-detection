import { useState, useEffect } from 'react';
import AddRule from './AddRule';
import RuleEditor from './RuleEditor';
import RulesList from './RulesList';
import RuleTest from './RuleTest';
import { WAFRule, RulesResponse, getCreatedDate, getUpdatedDate } from '../../types/waf';

export default function RulesContainer() {
  const [defaultRules, setDefaultRules] = useState<WAFRule[]>([]);
  const [customRules, setCustomRules] = useState<WAFRule[]>([]);
  const [view, setView] = useState<'list' | 'add' | 'edit'>('list');
  const [selectedRule, setSelectedRule] = useState<WAFRule | null>(null);
  const [editingRule, setEditingRule] = useState<WAFRule | null>(null);
  const [ruleForTest, setRuleForTest] = useState<WAFRule | null>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);

  // Carica le regole dal backend
  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/api/rules', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data: RulesResponse = await response.json();

      // Supporta sia snake_case che camelCase
      const defaults = data.default_rules || data.defaultRules || [];
      const customs = data.custom_rules || data.customRules || data.rules || [];

      setDefaultRules(defaults);
      setCustomRules(customs);
    } catch (error) {
      console.error('Failed to load rules:', error);
    }
  };

  const handleAddRule = (rule: WAFRule) => {
    setCustomRules([...customRules, rule]);
    setView('list');
  };

  const handleRuleUpdated = (updatedRule: WAFRule) => {
    setCustomRules(customRules.map(r => (r.id === updatedRule.id ? updatedRule : r)));
    setView('list');
    setEditingRule(null);
  };

  const handleDeleteRule = async (id: string) => {
    // Non permettere di eliminare le regole di default
    const isDefault = defaultRules.some(r => r.id === id);
    if (isDefault) {
      alert('Non è possibile eliminare le regole di default');
      return;
    }

    if (confirm('Sei sicuro di voler eliminare questa regola?')) {
      const token = localStorage.getItem('authToken');

      try {
        const response = await fetch(`/api/rules/${id}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          setCustomRules(customRules.filter(r => r.id !== id));
          setShowDetailsModal(false);
          alert('Regola eliminata con successo');
        }
      } catch (error) {
        console.error('Error deleting rule:', error);
        alert('Errore nell\'eliminazione della regola');
      }
    }
  };

  const handleToggleRule = async (id: string) => {
    // Non permettere di modificare le regole di default
    const isDefault = defaultRules.some(r => r.id === id);
    if (isDefault) {
      alert('Non è possibile modificare le regole di default');
      return;
    }

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
        setCustomRules(
          customRules.map(r =>
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

  const handleEditRule = (rule: WAFRule) => {
    setEditingRule(rule);
    setView('edit');
    setShowDetailsModal(false);
  };

  const handleViewDetails = (rule: WAFRule) => {
    setSelectedRule(rule);
    setShowDetailsModal(true);
  };

  const handleTestRule = (rule: WAFRule) => {
    setRuleForTest(rule);
    setShowTestModal(true);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">WAF Rules</h1>
          <p className="text-gray-400">Crea e gestisci le regole personalizzate del WAF</p>
        </div>
        {view === 'list' && (
          <button
            onClick={() => setView('add')}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
          >
            + Add Rule
          </button>
        )}
      </div>

      {/* Add Rule View */}
      {view === 'add' && (
        <AddRule
          onRuleAdded={handleAddRule}
          onCancel={() => setView('list')}
          allRules={rules}
        />
      )}

      {/* Edit Rule View */}
      {view === 'edit' && editingRule && (
        <RuleEditor
          rule={editingRule}
          onRuleUpdated={handleRuleUpdated}
          onCancel={() => {
            setView('list');
            setEditingRule(null);
          }}
          allRules={rules}
        />
      )}

      {/* Rules List View */}
      {view === 'list' && (
        <RulesList
          defaultRules={defaultRules}
          customRules={customRules}
          onEdit={handleEditRule}
          onDelete={handleDeleteRule}
          onToggle={handleToggleRule}
          onViewDetails={handleViewDetails}
        />
      )}

      {/* Details Modal */}
      {showDetailsModal && selectedRule && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full p-6 max-h-96 overflow-y-auto">
            <div className="flex justify-between items-start mb-6">
              <h2 className="text-2xl font-bold text-white">{selectedRule.name}</h2>
              <button
                onClick={() => setShowDetailsModal(false)}
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
                  <p className="text-gray-300 mt-1 font-medium">
                    {selectedRule.mode === 'block' ? '🚫 Blocca' : '🔍 Rileva'}
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
                    {getCreatedDate(selectedRule)}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Ultimo Aggiornamento</p>
                  <p className="text-gray-300 mt-1">
                    {getUpdatedDate(selectedRule)}
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
                  setShowDetailsModal(false);
                }}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium transition"
              >
                ✏️ Modifica
              </button>
              <button
                onClick={() => {
                  handleTestRule(selectedRule);
                  setShowDetailsModal(false);
                }}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded font-medium transition"
              >
                🧪 Testa
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
                onClick={() => setShowDetailsModal(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium ml-auto"
              >
                Chiudi
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Test Modal */}
      {showTestModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full p-6 max-h-screen overflow-y-auto">
            <div className="flex justify-between items-start mb-6">
              <h2 className="text-2xl font-bold text-white">Test Regola</h2>
              <button
                onClick={() => setShowTestModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ✕
              </button>
            </div>
            <RuleTest rule={ruleForTest} />
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setShowTestModal(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium"
              >
                Chiudi
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
