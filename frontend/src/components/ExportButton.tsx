import { useState } from 'react';
import { Download, FileJson, Check } from 'lucide-react';
import { ThreatIndicator } from '@/types/threat';
import { toast } from '@/hooks/use-toast';

interface ExportButtonProps {
  indicators: ThreatIndicator[];
}

export const ExportButton = ({ indicators }: ExportButtonProps) => {
  const [isExporting, setIsExporting] = useState(false);

  const exportToJson = () => {
    setIsExporting(true);
    
    const exportData = {
      exportedAt: new Date().toISOString(),
      totalIndicators: indicators.length,
      indicators: indicators.map(i => ({
        value: i.value,
        type: i.type,
        threatLevel: i.threatLevel,
        score: i.score,
        sources: i.sources,
        firstSeen: i.firstSeen.toISOString(),
        lastSeen: i.lastSeen.toISOString(),
        tags: i.tags,
        description: i.description,
        correlations: i.correlations,
      })),
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threat-intel-export-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setTimeout(() => {
      setIsExporting(false);
      toast({
        title: "Export Complete",
        description: `Exported ${indicators.length} indicators to JSON`,
      });
    }, 500);
  };

  return (
    <button
      onClick={exportToJson}
      disabled={isExporting || indicators.length === 0}
      className="px-4 py-2 rounded-md border border-primary bg-primary/10 text-primary hover:bg-primary/20 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {isExporting ? (
        <>
          <Check className="w-4 h-4 animate-pulse" />
          <span className="font-mono text-sm">Exporting...</span>
        </>
      ) : (
        <>
          <FileJson className="w-4 h-4" />
          <span className="font-mono text-sm">Export JSON</span>
          <span className="px-1.5 py-0.5 rounded bg-primary/20 text-xs font-mono">
            {indicators.length}
          </span>
        </>
      )}
    </button>
  );
};
