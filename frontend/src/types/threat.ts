export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type IOCType = 'ip' | 'domain' | 'hash' | 'url' | 'email';

export interface ThreatIndicator {
  id: string;
  value: string;
  type: IOCType;
  threatLevel: ThreatLevel;
  score: number; // 0-100
  sources: string[];
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
  description?: string;
  correlations?: string[]; // IDs of related IOCs
}

export interface ThreatFeed {
  id: string;
  name: string;
  description: string;
  url: string;
  lastUpdated: Date;
  indicatorCount: number;
  status: 'active' | 'inactive' | 'error';
  reliability: number; // 1-5
}

export interface ThreatStats {
  totalIndicators: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  activeFeeds: number;
  correlatedIOCs: number;
  last24hNew: number;
}

export interface FilterOptions {
  search: string;
  types: IOCType[];
  levels: ThreatLevel[];
  sources: string[];
  dateRange: {
    start: Date | null;
    end: Date | null;
  };
}
