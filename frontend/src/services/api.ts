/**
 * API Client for Threat Radar Backend
 */

import { ThreatIndicator, ThreatFeed, ThreatStats, IOCType, ThreatLevel } from '@/types/threat';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

// Generic fetch wrapper with error handling
async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}

// Fetch threat indicators with optional filtering
export async function fetchIndicators(params?: {
  search?: string;
  types?: IOCType[];
  levels?: ThreatLevel[];
  sources?: string[];
  limit?: number;
  offset?: number;
}): Promise<ThreatIndicator[]> {
  const queryParams = new URLSearchParams();

  if (params?.search) queryParams.append('search', params.search);
  if (params?.limit) queryParams.append('limit', params.limit.toString());
  if (params?.offset) queryParams.append('offset', params.offset.toString());

  // Add array parameters
  params?.types?.forEach(type => queryParams.append('types', type));
  params?.levels?.forEach(level => queryParams.append('levels', level));
  params?.sources?.forEach(source => queryParams.append('sources', source));

  const query = queryParams.toString();
  const endpoint = `/indicators${query ? `?${query}` : ''}`;

  const data = await apiFetch<any[]>(endpoint);

  // Transform snake_case to camelCase and convert date strings to Date objects
  return data.map(indicator => ({
    id: indicator.id,
    value: indicator.value,
    type: indicator.type,
    threatLevel: indicator.threat_level,
    score: indicator.score,
    sources: indicator.sources,
    firstSeen: new Date(indicator.first_seen),
    lastSeen: new Date(indicator.last_seen),
    tags: indicator.tags,
    description: indicator.description,
    correlations: indicator.correlations,
  }));
}

// Fetch all threat feeds metadata
export async function fetchFeeds(): Promise<ThreatFeed[]> {
  const data = await apiFetch<any[]>('/feeds');

  return data.map(feed => ({
    id: feed.id,
    name: feed.name,
    description: feed.description,
    url: feed.url,
    lastUpdated: new Date(feed.last_updated),
    indicatorCount: feed.indicator_count || 0,
    status: feed.status,
    reliability: feed.reliability,
  }));
}

// Fetch aggregate statistics
export async function fetchStatistics(): Promise<ThreatStats> {
  const data = await apiFetch<any>('/statistics');

  return {
    totalIndicators: data.total_indicators,
    criticalCount: data.critical_count,
    highCount: data.high_count,
    mediumCount: data.medium_count,
    lowCount: data.low_count,
    infoCount: data.info_count,
    activeFeeds: data.active_feeds,
    correlatedIOCs: data.correlated_iocs,
    last24hNew: data.last_24h_new,
  };
}

// Fetch a specific indicator by ID
export async function fetchIndicatorById(id: string): Promise<ThreatIndicator> {
  const data = await apiFetch<any>(`/indicators/${id}`);

  return {
    id: data.id,
    value: data.value,
    type: data.type,
    threatLevel: data.threat_level,
    score: data.score,
    sources: data.sources,
    firstSeen: new Date(data.first_seen),
    lastSeen: new Date(data.last_seen),
    tags: data.tags,
    description: data.description,
    correlations: data.correlations,
  };
}

// Trigger manual feed update
export async function triggerFeedUpdate(): Promise<{ status: string; message: string }> {
  return apiFetch('/feeds/update', { method: 'POST' });
}

// Health check
export async function checkHealth(): Promise<{
  status: string;
  timestamp: string;
  version: string;
  feeds_healthy: number;
  total_iocs: number;
}> {
  return apiFetch('/health');
}
