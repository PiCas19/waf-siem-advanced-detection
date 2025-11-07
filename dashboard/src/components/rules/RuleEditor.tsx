import React, { useState } from 'react';
import { WAFRule } from '../../types/waf';
import { useToast } from '@/contexts/SnackbarContext';

interface RuleEditorProps {
  rule: WAFRule;
  onRuleUpdated: (rule: WAFRule) => void;
  onCancel: () => void;
}

export default function RuleEditor({ rule, onRuleUpdated, onCancel }: RuleEditorProps) {
  const { showToast } = useToast();
  const [formData, setFormData] = useState({
    name: rule.name,
    pattern: rule.pattern,
    description: rule.description,
    threatType: rule.threatType || rule.type,
    // Map action 'log' -> 'detect', 'block' -> 'block'
    mode: (rule.action === 'log' ? 'detect' : rule.mode || 'block') as 'detect' | 'block',
    // Map individual enabled flags back to blockAction
    blockAction: ((rule as any).block_enabled ? 'block' :
                  (rule as any).drop_enabled ? 'drop' :
                  (rule as any).redirect_enabled ? 'redirect' :
                  (rule as any).challenge_enabled ? 'challenge' :
                  'none') as 'none' | 'block' | 'drop' | 'redirect' | 'challenge',
    redirectUrl: (rule as any).redirect_url || '',
  });

  const threatTypes = [
    'Command Injection',
    'LDAP Injection',
    'Local File Inclusion',
    'NoSQL Injection',
    'Path Traversal',
    'Prototype Pollution',
    'Response Splitting',
    'Remote File Inclusion',
    'SQL Injection',
    'SSRF',
    'Server-Side Template Injection',
    'Cross-Site Scripting',
    'XML External Entity',
    'Other'
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name || !formData.pattern) {
      showToast('Nome e Pattern sono obbligatori', 'info', 4000);
      return;
    }

    const token = localStorage.getItem('authToken');

    // Map mode to action: 'detect' -> 'log', 'block' -> 'block'
    // Map blockAction to individual enabled flags for backend compatibility
    const payload = {
      name: formData.name,
      pattern: formData.pattern,
      description: formData.description,
      type: formData.threatType,
      action: formData.mode === 'detect' ? 'log' : 'block',
      block_enabled: formData.mode === 'block' && formData.blockAction === 'block',
      drop_enabled: formData.mode === 'block' && formData.blockAction === 'drop',
      redirect_enabled: formData.mode === 'block' && formData.blockAction === 'redirect',
      challenge_enabled: formData.mode === 'block' && formData.blockAction === 'challenge',
      redirect_url: (formData.mode === 'block' && formData.blockAction === 'redirect') ? formData.redirectUrl : '',
    };

    try {
      const response = await fetch(`/api/rules/${rule.id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const data = await response.json();
        onRuleUpdated(data.rule);
        showToast('Regola aggiornata con successo', 'success', 4000);
      } else {
        showToast('Errore nell\'aggiornamento della regola', 'error', 4000);
      }
    } catch (error) {
      showToast('Errore nel salvataggio della regola', 'error', 4000);
    }
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
      <h2 className="text-xl font-semibold text-white mb-6">Edit Rule</h2>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Name */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Rule Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g. SQL Injection Prevention"
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
            placeholder="e.g. SELECT|INSERT|UPDATE|DELETE|DROP"
            rows={3}
            className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none font-mono text-sm"
          />
          <p className="text-xs text-gray-400 mt-1">
            Enter a regular expression to match attack patterns
          </p>
        </div>

        {/* Description */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
          <textarea
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            placeholder="Rule description..."
            rows={2}
            className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Threat Type */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Threat Type
            </label>
            <select
              value={formData.threatType}
              onChange={(e) => setFormData({ ...formData, threatType: e.target.value })}
              className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              {threatTypes.map(type => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>

          {/* Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Mode</label>
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
                <span className="text-gray-300">Detect</span>
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
                <span className="text-gray-300">Block</span>
              </label>
            </div>
          </div>
        </div>

        {/* Automated Blocking Actions - Only available in Block mode */}
        <div className={formData.mode === 'detect' ? 'opacity-50 pointer-events-none' : ''}>
          <label className="block text-sm font-medium text-gray-300 mb-3">
            Blocking Action {formData.mode === 'detect' && <span className="text-xs text-gray-500">(disabled in Detect mode)</span>}
          </label>
          <div className="space-y-2">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="radio"
                name="blockAction"
                value="none"
                checked={formData.blockAction === 'none'}
                onChange={(e) => setFormData({ ...formData, blockAction: e.target.value as any })}
                disabled={formData.mode === 'detect'}
                className="w-4 h-4"
              />
              <span className="text-gray-300">None - Only log the threat</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="radio"
                name="blockAction"
                value="block"
                checked={formData.blockAction === 'block'}
                onChange={(e) => setFormData({ ...formData, blockAction: e.target.value as any })}
                disabled={formData.mode === 'detect'}
                className="w-4 h-4"
              />
              <span className="text-gray-300">Block - Reject request with 403 Forbidden</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="radio"
                name="blockAction"
                value="drop"
                checked={formData.blockAction === 'drop'}
                onChange={(e) => setFormData({ ...formData, blockAction: e.target.value as any })}
                disabled={formData.mode === 'detect'}
                className="w-4 h-4"
              />
              <span className="text-gray-300">Drop - Terminate connection immediately (no response)</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="radio"
                name="blockAction"
                value="redirect"
                checked={formData.blockAction === 'redirect'}
                onChange={(e) => setFormData({ ...formData, blockAction: e.target.value as any })}
                disabled={formData.mode === 'detect'}
                className="w-4 h-4"
              />
              <span className="text-gray-300">Redirect - Send to security/error page</span>
            </label>
            {formData.blockAction === 'redirect' && formData.mode === 'block' && (
              <div className="ml-7 mt-2">
                <input
                  type="text"
                  value={formData.redirectUrl}
                  onChange={(e) => setFormData({ ...formData, redirectUrl: e.target.value })}
                  placeholder="https://example.com/security"
                  className="w-full px-3 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
                />
              </div>
            )}
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="radio"
                name="blockAction"
                value="challenge"
                checked={formData.blockAction === 'challenge'}
                onChange={(e) => setFormData({ ...formData, blockAction: e.target.value as any })}
                disabled={formData.mode === 'detect'}
                className="w-4 h-4"
              />
              <span className="text-gray-300">Challenge - Require CAPTCHA verification</span>
            </label>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex gap-4 pt-4">
          <button
            type="submit"
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium transition"
          >
            Save Changes
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}