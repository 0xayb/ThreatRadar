import { ThreatFeed } from '@/types/threat';
import { Badge } from '@/components/ui/badge';
import { formatDistanceToNow } from 'date-fns';
import { ExternalLink, RefreshCw, Star } from 'lucide-react';

interface FeedStatusProps {
  feeds: ThreatFeed[];
}

export const FeedStatus = ({ feeds }: FeedStatusProps) => {
  return (
    <div className="p-4 rounded-lg border border-border bg-card terminal-card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-muted-foreground">Threat Feeds</h3>
        <button className="p-1.5 rounded hover:bg-secondary transition-colors">
          <RefreshCw className="w-4 h-4 text-muted-foreground" />
        </button>
      </div>
      
      <div className="space-y-3">
        {feeds.map((feed) => (
          <div 
            key={feed.id} 
            className="p-3 rounded-md bg-secondary/50 border border-border hover:border-primary/30 transition-colors animate-fade-in"
          >
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-medium">{feed.name}</span>
                <Badge variant={feed.status}>{feed.status}</Badge>
              </div>
              <a 
                href={feed.url} 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
            
            <p className="text-xs text-muted-foreground mb-2 line-clamp-1">
              {feed.description}
            </p>
            
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-1">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Star 
                    key={i} 
                    className={`w-3 h-3 ${i < feed.reliability ? 'text-warning fill-warning' : 'text-muted'}`} 
                  />
                ))}
              </div>
              <span className="font-mono text-muted-foreground">
                {(feed.indicatorCount || 0).toLocaleString()} IOCs
              </span>
              <span className="font-mono text-muted-foreground">
                {feed.lastUpdated && !isNaN(feed.lastUpdated.getTime())
                  ? formatDistanceToNow(feed.lastUpdated, { addSuffix: true })
                  : 'Unknown'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
