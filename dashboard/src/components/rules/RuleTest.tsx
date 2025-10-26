import { useState } from 'react';
import { WAFRule, RuleTestResult, isTestableRule } from '../../types/waf';

interface RuleTestProps {
  rule?: WAFRule;
}

export default function RuleTest({ rule }: RuleTestProps) {
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [testError, setTestError] = useState('');

  const handleTest = () => {
    if (!isTestableRule(rule)) {
      setTestError('La regola selezionata non ha pattern e modalità definiti');
      return;
    }

    if (!testInput.trim()) {
      setTestError('Inserisci del testo da testare');
      return;
    }

    try {
      const regex = new RegExp(rule.pattern, 'gi');
      const matched = regex.test(testInput);

      setTestResult({
        matched,
        message: matched
          ? `Pattern trovato! La regola "${rule.name}" in modalità ${rule.mode === 'block' ? 'BLOCCO' : 'RILEVAMENTO'} avrebbe ${rule.mode === 'block' ? 'BLOCCATO' : 'RILEVATO'} questa richiesta.`
          : `Pattern non trovato. La regola non si attiverebbe per questo input.`,
      });
      setTestError('');
    } catch (error) {
      setTestError('Errore nel pattern regex: ' + (error instanceof Error ? error.message : 'Errore sconosciuto'));
      setTestResult(null);
    }
  };

  const handleClear = () => {
    setTestInput('');
    setTestResult(null);
    setTestError('');
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
      <h2 className="text-xl font-semibold text-white mb-6">Test Regola</h2>

      {isTestableRule(rule) ? (
        <>
          <div className="mb-6 p-4 bg-gray-700 rounded border border-gray-600">
            <p className="text-sm text-gray-400">Regola in test:</p>
            <p className="text-white font-semibold mt-1">{rule.name}</p>
            <p className="text-gray-400 text-sm mt-1">Pattern: <code className="bg-gray-800 px-2 py-1 rounded">{rule.pattern || 'N/A'}</code></p>
            {rule.severity && (
              <p className="text-gray-400 text-sm mt-1">Severità: <span className="text-yellow-400">{rule.severity}</span></p>
            )}
          </div>

          <div className="space-y-6">
            {/* Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Testo da Testare
              </label>
              <textarea
                value={testInput}
                onChange={(e) => setTestInput(e.target.value)}
                placeholder="Inserisci il testo che vuoi testare contro questa regola..."
                rows={5}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none font-mono text-sm"
              />
              <p className="text-xs text-gray-400 mt-1">
                Inserisci un payload di attacco (es: SELECT * FROM users WHERE id=1) per testare il pattern
              </p>
            </div>

            {/* Error */}
            {testError && (
              <div className="p-4 bg-red-500/20 border border-red-500/50 rounded">
                <p className="text-red-300 text-sm">{testError}</p>
              </div>
            )}

            {/* Result */}
            {testResult && (
              <div
                className={`p-4 rounded border ${
                  testResult.matched
                    ? 'bg-red-500/20 border-red-500/50'
                    : 'bg-green-500/20 border-green-500/50'
                }`}
              >
                <p
                  className={`font-semibold ${
                    testResult.matched ? 'text-red-300' : 'text-green-300'
                  }`}
                >
                  {testResult.matched ? '🚨 MATCH RILEVATO' : '✓ NO MATCH'}
                </p>
                <p
                  className={`text-sm mt-2 ${
                    testResult.matched ? 'text-red-200' : 'text-green-200'
                  }`}
                >
                  {testResult.message}
                </p>
              </div>
            )}

            {/* Buttons */}
            <div className="flex gap-4">
              <button
                onClick={handleTest}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium transition"
              >
                🧪 Testa Regola
              </button>
              <button
                onClick={handleClear}
                className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition"
              >
                Cancella
              </button>
            </div>
          </div>
        </>
      ) : (
        <div className="text-center py-8">
          <p className="text-gray-400">Seleziona una regola dalla lista per testarla</p>
        </div>
      )}
    </div>
  );
}