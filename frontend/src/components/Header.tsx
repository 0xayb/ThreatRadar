import { Shield, Activity, Terminal } from 'lucide-react';

export const Header = () => {
  return (
    <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-8 h-8 text-primary" />
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-primary rounded-full animate-pulse-glow" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-mono gradient-text">
                ThreatRadar
              </h1>
              <p className="text-xs text-muted-foreground font-mono">
                Open Source Threat Intelligence Platform
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-secondary rounded-md border border-border">
              <Activity className="w-4 h-4 text-primary animate-pulse" />
              <span className="text-sm font-mono text-muted-foreground">
                Live Feed
              </span>
            </div>
            
            <div className="flex items-center gap-2 px-3 py-1.5 bg-muted rounded-md border border-border">
              <Terminal className="w-4 h-4 text-accent" />
              <span className="text-sm font-mono text-muted-foreground">
                v1.0.0
              </span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
