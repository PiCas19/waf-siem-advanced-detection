import { useQuery } from '@tanstack/react-query';
import { fetchRules } from '@/services/api';
import { Card } from '@/components/common/Card';

export default function RulesList() {
  const { data: rules = [] } = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
  });

  return (
    <Card title="Active Rules">
      <div className="space-y-2">
        {rules.length === 0 ? (
          <p className="text-gray-400">No rules loaded</p>
        ) : (
          rules.map((rule: any) => (
            <div key={rule.id} className="flex justify-between items-center p-2 bg-gray-700 rounded">
              <span>{rule.name}</span>
              <span className={`text-xs px-2 py-1 rounded ${rule.severity === 'CRITICAL' ? 'bg-red-600' : 'bg-yellow-600'}`}>
                {rule.severity}
              </span>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}