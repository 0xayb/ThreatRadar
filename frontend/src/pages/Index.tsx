import { useState, useEffect } from 'react';
import { Header } from '@/components/Header';
import { StatsCard } from '@/components/StatsCard';
import { ThreatLevelChart } from '@/components/ThreatLevelChart';
import { FeedStatus } from '@/components/FeedStatus';
import { SearchFilter } from '@/components/SearchFilter';
import { ThreatTable } from '@/components/ThreatTable';
import { ExportButton } from '@/components/ExportButton';
import { IOCType, ThreatLevel, ThreatIndicator, ThreatFeed, ThreatStats } from '@/types/threat';
import { fetchIndicators, fetchFeeds, fetchStatistics } from '@/services/api';
import { 
  AlertTriangle, 
  Shield, 
  Database, 
  Activity, 
  Link2, 
  Clock 
} from 'lucide-react';

const Index = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTypes, setSelectedTypes] = useState<IOCType[]>([]);
  const [selectedLevels, setSelectedLevels] = useState<ThreatLevel[]>([]);
  
  // Data from API
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [stats, setStats] = useState<ThreatStats>({
    totalIndicators: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    activeFeeds: 0,
    correlatedIOCs: 0,
    last24hNew: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch data from API
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Fetch all data in parallel
        const [indicatorsData, feedsData, statsData] = await Promise.all([
          fetchIndicators({
            search: searchQuery || undefined,
            types: selectedTypes.length > 0 ? selectedTypes : undefined,
            levels: selectedLevels.length > 0 ? selectedLevels : undefined,
            limit: 1000,
          }),
          fetchFeeds(),
          fetchStatistics(),
        ]);
        
        setIndicators(indicatorsData);
        setFeeds(feedsData);
        setStats(statsData);
      } catch (err) {
        console.error('Error loading data:', err);
        setError('Failed to load threat intelligence data. Please ensure the backend is running.');
      } finally {
        setLoading(false);
      }
    };

    loadData();
    
    // Refresh data every 60 seconds
    const interval = setInterval(loadData, 60000);
    return () => clearInterval(interval);
  }, [searchQuery, selectedTypes, selectedLevels]);


  if (loading && indicators.length === 0) {
    return (
      <div className="min-h-screen bg-background cyber-grid flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading threat intelligence...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background cyber-grid flex items-center justify-center">
        <div className="text-center max-w-md">
          <AlertTriangle className="w-12 h-12 text-destructive mx-auto mb-4" />
          <h2 className="text-xl font-semibold mb-2">Connection Error</h2>
          <p className="text-muted-foreground mb-4">{error}</p>
          <p className="text-sm text-muted-foreground">
            Make sure the backend API is running on http://localhost:8000
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background cyber-grid">
      <Header />
      
      <main className="container mx-auto px-4 py-6 space-y-6">
        {/* Stats Overview */}
        <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatsCard
            title="Total IOCs"
            value={stats.totalIndicators}
            icon={Database}
            trend={{ value: 12, isPositive: true }}
          />
          <StatsCard
            title="Critical"
            value={stats.criticalCount}
            icon={AlertTriangle}
            variant="critical"
          />
          <StatsCard
            title="High"
            value={stats.highCount}
            icon={Shield}
            variant="high"
          />
          <StatsCard
            title="Active Feeds"
            value={stats.activeFeeds}
            icon={Activity}
            variant="info"
          />
          <StatsCard
            title="Correlated"
            value={stats.correlatedIOCs}
            icon={Link2}
            variant="low"
          />
          <StatsCard
            title="New (24h)"
            value={stats.last24hNew}
            icon={Clock}
            trend={{ value: 8, isPositive: false }}
          />
        </section>

        {/* Charts and Feeds */}
        <section className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <ThreatLevelChart stats={stats} />
          </div>
          <div>
            <FeedStatus feeds={feeds} />
          </div>
        </section>

        {/* Search and Filter */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold font-mono">
              <span className="text-primary">&gt;</span> Threat Indicators
            </h2>
            <ExportButton indicators={indicators} />
          </div>
          
          <SearchFilter
            onSearchChange={setSearchQuery}
            onTypeFilter={setSelectedTypes}
            onLevelFilter={setSelectedLevels}
            selectedTypes={selectedTypes}
            selectedLevels={selectedLevels}
          />
        </section>

        {/* Threat Table */}
        <section>
          <ThreatTable indicators={indicators} />
        </section>

        {/* Footer */}
        <footer className="border-t border-border pt-6 pb-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              <span>Threat Radar v1.0.0 | Educational Tool</span>
            </div>
            <div className="flex items-center gap-4">
              <span>⚠️ For authorized security research only</span>
              <span className="text-primary">MIT License</span>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
};

export default Index;
