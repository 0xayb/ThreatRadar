import { useState } from 'react';
import { ThreatIndicator } from '@/types/threat';
import { Badge } from '@/components/ui/badge';
import { formatDistanceToNow } from 'date-fns';
import { ChevronDown, ChevronUp, Copy, CheckCircle, Link2 } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface ThreatTableProps {
  indicators: ThreatIndicator[];
}

type SortField = 'score' | 'lastSeen' | 'type' | 'threatLevel';
type SortDirection = 'asc' | 'desc';

export const ThreatTable = ({ indicators }: ThreatTableProps) => {
  const [sortField, setSortField] = useState<SortField>('score');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const sortedIndicators = [...indicators].sort((a, b) => {
    let comparison = 0;
    switch (sortField) {
      case 'score':
        comparison = a.score - b.score;
        break;
      case 'lastSeen':
        comparison = a.lastSeen.getTime() - b.lastSeen.getTime();
        break;
      case 'type':
        comparison = a.type.localeCompare(b.type);
        break;
      case 'threatLevel':
        const levelOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        comparison = levelOrder[a.threatLevel] - levelOrder[b.threatLevel];
        break;
    }
    return sortDirection === 'asc' ? comparison : -comparison;
  });

  const copyToClipboard = async (value: string, id: string) => {
    await navigator.clipboard.writeText(value);
    setCopiedId(id);
    toast({
      title: "Copied to clipboard",
      description: value.length > 50 ? value.substring(0, 50) + '...' : value,
    });
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-destructive';
    if (score >= 60) return 'text-orange-400';
    if (score >= 40) return 'text-warning';
    if (score >= 20) return 'text-primary';
    return 'text-accent';
  };

  const toggleRowExpansion = (id: string) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDirection === 'asc' ? (
      <ChevronUp className="w-4 h-4" />
    ) : (
      <ChevronDown className="w-4 h-4" />
    );
  };

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-secondary/50 border-b border-border">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground">
                IOC Value
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                onClick={() => handleSort('type')}
              >
                <div className="flex items-center gap-1">
                  Type
                  <SortIcon field="type" />
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                onClick={() => handleSort('threatLevel')}
              >
                <div className="flex items-center gap-1">
                  Level
                  <SortIcon field="threatLevel" />
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                onClick={() => handleSort('score')}
              >
                <div className="flex items-center gap-1">
                  Score
                  <SortIcon field="score" />
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground">
                Sources
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground">
                Tags
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                onClick={() => handleSort('lastSeen')}
              >
                <div className="flex items-center gap-1">
                  Last Seen
                  <SortIcon field="lastSeen" />
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {sortedIndicators.map((indicator, index) => (
              <tr 
                key={indicator.id} 
                className="data-row border-b border-border last:border-0"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-sm text-foreground max-w-[280px] truncate block">
                      {indicator.value}
                    </code>
                    {indicator.correlations && indicator.correlations.length > 0 && (
                      <span className="text-accent" title={`${indicator.correlations.length} correlations`}>
                        <Link2 className="w-4 h-4" />
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <Badge variant={indicator.type}>{indicator.type.toUpperCase()}</Badge>
                </td>
                <td className="px-4 py-3">
                  <Badge variant={indicator.threatLevel} className="capitalize">
                    {indicator.threatLevel}
                  </Badge>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-2 rounded-full bg-secondary overflow-hidden">
                      <div 
                        className={`h-full rounded-full transition-all ${
                          indicator.score >= 80 ? 'bg-destructive' :
                          indicator.score >= 60 ? 'bg-orange-500' :
                          indicator.score >= 40 ? 'bg-warning' :
                          indicator.score >= 20 ? 'bg-primary' : 'bg-accent'
                        }`}
                        style={{ width: `${indicator.score}%` }}
                      />
                    </div>
                    <span className={`font-mono text-sm font-semibold ${getScoreColor(indicator.score)}`}>
                      {indicator.score}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap max-w-[150px]">
                    {indicator.sources.slice(0, 2).map((source) => (
                      <span 
                        key={source} 
                        className="text-xs text-muted-foreground font-mono bg-secondary px-1.5 py-0.5 rounded"
                      >
                        {source.split(' ')[0]}
                      </span>
                    ))}
                    {indicator.sources.length > 2 && (
                      <span className="text-xs text-muted-foreground">
                        +{indicator.sources.length - 2}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap max-w-[150px]">
                    {expandedRows.has(indicator.id) ? (
                      // Show all tags when expanded
                      indicator.tags.map((tag) => (
                        <span
                          key={tag}
                          className="text-xs text-primary font-mono bg-primary/10 px-1.5 py-0.5 rounded"
                        >
                          {tag}
                        </span>
                      ))
                    ) : (
                      // Show first 2 tags when collapsed
                      <>
                        {indicator.tags.slice(0, 2).map((tag) => (
                          <span
                            key={tag}
                            className="text-xs text-primary font-mono bg-primary/10 px-1.5 py-0.5 rounded"
                          >
                            {tag}
                          </span>
                        ))}
                        {indicator.tags.length > 2 && (
                          <button
                            onClick={() => toggleRowExpansion(indicator.id)}
                            className="text-xs text-muted-foreground hover:text-primary transition-colors cursor-pointer"
                          >
                            +{indicator.tags.length - 2}
                          </button>
                        )}
                      </>
                    )}
                    {expandedRows.has(indicator.id) && indicator.tags.length > 2 && (
                      <button
                        onClick={() => toggleRowExpansion(indicator.id)}
                        className="text-xs text-muted-foreground hover:text-primary transition-colors cursor-pointer"
                      >
                        Show less
                      </button>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-muted-foreground font-mono">
                    {indicator.lastSeen && !isNaN(indicator.lastSeen.getTime())
                      ? formatDistanceToNow(indicator.lastSeen, { addSuffix: true })
                      : 'Unknown'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => copyToClipboard(indicator.value, indicator.id)}
                    className="p-1.5 rounded hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground"
                    title="Copy IOC value"
                  >
                    {copiedId === indicator.id ? (
                      <CheckCircle className="w-4 h-4 text-primary" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {sortedIndicators.length === 0 && (
        <div className="p-8 text-center">
          <p className="text-muted-foreground font-mono">No indicators match your filters</p>
        </div>
      )}
    </div>
  );
};
