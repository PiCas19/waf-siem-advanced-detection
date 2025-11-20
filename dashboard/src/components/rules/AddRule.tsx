import React, { useState } from 'react';
import { WAFRule } from '../../types/waf';
import { useToast } from '@/contexts/SnackbarContext';

interface AddRuleProps {
  onRuleAdded: (rule: WAFRule) => void;
  onCancel: () => void;
}

export default function AddRule({ onRuleAdded, onCancel }: AddRuleProps) {
  const { showToast } = useToast();
  const [formData, setFormData] = useState({
    name: '',
    pattern: '',
    description: '',
    threatType: 'SQL Injection',
    severity: 'medium' as 'low' | 'medium' | 'high' | 'critical',
    mode: 'block' as 'block' | 'detect',
    blockAction: 'none' as 'none' | 'block' | 'drop' | 'redirect' | 'challenge',
    redirectUrl: '',
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
      showToast('Rule name and pattern are required', 'info', 4000);
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
      severity: formData.severity,
      action: formData.mode === 'detect' ? 'log' : 'block',
      block_enabled: formData.mode === 'block' && formData.blockAction === 'block',
      drop_enabled: formData.mode === 'block' && formData.blockAction === 'drop',
      redirect_enabled: formData.mode === 'block' && formData.blockAction === 'redirect',
      challenge_enabled: formData.mode === 'block' && formData.blockAction === 'challenge',
      redirect_url: (formData.mode === 'block' && formData.blockAction === 'redirect') ? formData.redirectUrl : '',
    };

    try {
      const response = await fetch('/api/rules', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const data = await response.json();
        onRuleAdded(data.rule);
        showToast('Rule created successfully', 'success', 4000);
        setFormData({
          name: '',
          pattern: '',
          description: '',
          threatType: 'SQL Injection',
          severity: 'medium',
          mode: 'block',
          blockAction: 'none',
          redirectUrl: '',
        });
      } else {
        showToast('Error creating rule', 'error', 4000);
      }
    } catch (error) {
      showToast('Error saving rule', 'error', 4000);
    }
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
      <h2 className="text-xl font-semibold text-white mb-6">Create New Rule</h2>

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

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
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

          {/* Severity */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Severity Level
            </label>
            <select
              value={formData.severity}
              onChange={(e) => setFormData({ ...formData, severity: e.target.value as 'low' | 'medium' | 'high' | 'critical' })}
              className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
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
            Create Rule
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
