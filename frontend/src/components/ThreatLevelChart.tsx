import { ThreatStats } from '@/types/threat';

interface ThreatLevelChartProps {
  stats: ThreatStats;
}

export const ThreatLevelChart = ({ stats }: ThreatLevelChartProps) => {
  const total = stats.totalIndicators;
  
  const levels = [
    { label: 'Critical', count: stats.criticalCount, color: 'bg-destructive', percentage: (stats.criticalCount / total) * 100 },
    { label: 'High', count: stats.highCount, color: 'bg-orange-500', percentage: (stats.highCount / total) * 100 },
    { label: 'Medium', count: stats.mediumCount, color: 'bg-warning', percentage: (stats.mediumCount / total) * 100 },
    { label: 'Low', count: stats.lowCount, color: 'bg-primary', percentage: (stats.lowCount / total) * 100 },
    { label: 'Info', count: stats.infoCount, color: 'bg-accent', percentage: (stats.infoCount / total) * 100 },
  ];

  return (
    <div className="p-4 rounded-lg border border-border bg-card terminal-card">
      <h3 className="text-sm font-semibold text-muted-foreground mb-4">Threat Level Distribution</h3>
      
      {/* Bar visualization */}
      <div className="h-4 rounded-full overflow-hidden flex mb-4 bg-secondary">
        {levels.map((level, index) => (
          <div
            key={level.label}
            className={`${level.color} transition-all duration-500`}
            style={{ 
              width: `${level.percentage}%`,
              animationDelay: `${index * 100}ms`
            }}
          />
        ))}
      </div>
      
      {/* Legend */}
      <div className="grid grid-cols-5 gap-2">
        {levels.map((level) => (
          <div key={level.label} className="text-center">
            <div className="flex items-center justify-center gap-1.5 mb-1">
              <div className={`w-2 h-2 rounded-full ${level.color}`} />
              <span className="text-xs text-muted-foreground">{level.label}</span>
            </div>
            <p className="text-lg font-bold font-mono">{level.count}</p>
            <p className="text-xs text-muted-foreground font-mono">
              {level.percentage.toFixed(1)}%
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
