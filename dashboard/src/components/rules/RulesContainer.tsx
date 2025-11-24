import { useState, useEffect } from 'react';
import AddRule from './AddRule';
import RuleEditor from './RuleEditor';
import RulesList from './RulesList';
import RuleTest from './RuleTest';
import { WAFRule, RulesResponse, getCreatedDate, getUpdatedDate } from '../../types/waf';
import { useToast } from '@/contexts/SnackbarContext';

export default function RulesContainer() {
  const { showToast } = useToast();
  const [defaultRules, setDefaultRules] = useState<WAFRule[]>([]);
  const [customRules, setCustomRules] = useState<WAFRule[]>([]);
  const [view, setView] = useState<'list' | 'add' | 'edit'>('list');
  const [selectedRule, setSelectedRule] = useState<WAFRule | null>(null);
  const [editingRule, setEditingRule] = useState<WAFRule | null>(null);
  const [ruleForTest, setRuleForTest] = useState<WAFRule | undefined>(undefined);
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
    // Don't allow deleting default rules
    const isDefault = defaultRules.some(r => r.id === id);
    if (isDefault) {
      showToast('Cannot delete default rules', 'info', 4000);
      return;
    }

    if (confirm('Are you sure you want to delete this rule?')) {
      const token = localStorage.getItem('authToken');

      try {
        const response = await fetch(`/api/rules/${id}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          setCustomRules(customRules.filter(r => r.id !== id));
          setShowDetailsModal(false);
          showToast('Rule deleted successfully', 'success', 4000);

          // If this was a manual block rule, trigger stats page refresh
          if (data.manual_block_deleted) {
            if (typeof window !== 'undefined') {
              const refreshEvent = new CustomEvent('statsRefresh', { detail: { timestamp: Date.now() } });
              window.dispatchEvent(refreshEvent);
            }
          }
        } else {
          const errorData = await response.json();
          showToast('Error deleting rule: ' + (errorData.error || 'Unknown error'), 'error', 4000);
        }
      } catch (error) {
        showToast('Error deleting rule', 'error', 4000);
      }
    }
  };

  const handleToggleRule = async (id: string) => {
    // Don't allow modifying default rules
    const isDefault = defaultRules.some(r => r.id === id);
    if (isDefault) {
      showToast('Cannot modify default rules', 'info', 4000);
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
          <p className="text-gray-400">Create and manage custom WAF rules</p>
        </div>
        {view === 'list' && (
          <button
            onClick={() => setView('add')}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
          >
            Add Rule
          </button>
        )}
      </div>

      {/* Add Rule View */}
      {view === 'add' && (
        <AddRule
          onRuleAdded={handleAddRule}
          onCancel={() => setView('list')}
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
                ×
              </button>
            </div>

            <div className="space-y-4">
              {/* Manual Block Indicator */}
              {(selectedRule as any).is_manual_block && (
                <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-3">
                  <p className="text-blue-300 text-sm font-medium">
                    🔒 Manual Block Rule
                  </p>
                  <p className="text-blue-200 text-xs mt-1">
                    This rule was created by manually blocking a threat from the dashboard. It cannot be edited directly.
                  </p>
                </div>
              )}

              <div>
                <p className="text-sm text-gray-400">Description</p>
                <p className="text-gray-300 mt-1">{selectedRule.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-400">Threat Type</p>
                  <p className="text-gray-300 mt-1 font-medium">{selectedRule.type || selectedRule.threatType}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Mode</p>
                  <p className="text-gray-300 mt-1 font-medium">
                    {defaultRules.some(r => r.id === selectedRule.id)
                      ? 'Detect & Block'
                      : (selectedRule.action === 'block' || selectedRule.mode === 'block' ? 'Block' : 'Detect')}
                  </p>
                </div>
              </div>

              {selectedRule.severity && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-400">Severity</p>
                    <span className={`px-3 py-1 rounded text-xs font-medium mt-1 inline-block ${
                      selectedRule.severity === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-300'
                        : selectedRule.severity === 'HIGH'
                        ? 'bg-orange-500/20 text-orange-300'
                        : 'bg-yellow-500/20 text-yellow-300'
                    }`}>
                      {selectedRule.severity}
                    </span>
                  </div>
                </div>
              )}

              {selectedRule.examples && selectedRule.examples.length > 0 && (
                <div>
                  <p className="text-sm text-gray-400">Examples</p>
                  <ul className="mt-2 space-y-2">
                    {selectedRule.examples.slice(0, 3).map((ex, idx) => (
                      <li key={idx} className="text-gray-400 text-sm break-all">
                        • <code className="bg-gray-700 px-2 py-1 rounded text-xs">{ex}</code>
                      </li>
                    ))}
                    {selectedRule.examples.length > 3 && (
                      <li className="text-gray-500 text-sm italic">+ {selectedRule.examples.length - 3} more examples</li>
                    )}
                  </ul>
                </div>
              )}

              {selectedRule.pattern && (
                <div>
                  <p className="text-sm text-gray-400">Pattern (Regex)</p>
                  <div className="bg-gray-700 p-3 rounded mt-1 font-mono text-sm text-gray-300 break-all">
                    {selectedRule.pattern}
                  </div>
                </div>
              )}

              {/* Show timestamps only for custom rules (not default) */}
              {!defaultRules.some(r => r.id === selectedRule.id) && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-400">Created</p>
                    <p className="text-gray-300 mt-1">
                      {getCreatedDate(selectedRule)}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Last Updated</p>
                    <p className="text-gray-300 mt-1">
                      {getUpdatedDate(selectedRule)}
                    </p>
                  </div>
                </div>
              )}

              <div>
                <p className="text-sm text-gray-400">Status</p>
                <p className="text-gray-300 mt-1">
                  {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                </p>
              </div>
            </div>

            <div className="flex gap-4 mt-6 pt-6 border-t border-gray-700">
              {/* Check if this is a default rule */}
              {!defaultRules.some(r => r.id === selectedRule.id) ? (
                <>
                  <button
                    onClick={() => {
                      handleEditRule(selectedRule);
                      setShowDetailsModal(false);
                    }}
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium transition"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => {
                      handleDeleteRule(selectedRule.id);
                    }}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium transition"
                  >
                    Delete
                  </button>
                </>
              ) : (
                <div className="text-sm text-blue-300 italic">
                  This is a built-in rule and cannot be edited or deleted
                </div>
              )}
              <button
                onClick={() => {
                  handleTestRule(selectedRule);
                  setShowDetailsModal(false);
                }}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded font-medium transition"
              >
                Test
              </button>
              <button
                onClick={() => setShowDetailsModal(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium ml-auto"
              >
                Close
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
              <h2 className="text-2xl font-bold text-white">Test Rule</h2>
              <button
                onClick={() => setShowTestModal(false)}
                className="text-gray-400 hover:text-white text-lg font-bold"
              >
                ×
              </button>
            </div>
            <RuleTest rule={ruleForTest} />
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setShowTestModal(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
