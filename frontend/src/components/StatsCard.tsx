import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatsCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const variantStyles = {
  default: 'border-border',
  critical: 'border-destructive/50 bg-destructive/5',
  high: 'border-orange-500/50 bg-orange-500/5',
  medium: 'border-warning/50 bg-warning/5',
  low: 'border-primary/50 bg-primary/5',
  info: 'border-accent/50 bg-accent/5',
};

const iconVariantStyles = {
  default: 'text-muted-foreground',
  critical: 'text-destructive',
  high: 'text-orange-400',
  medium: 'text-warning',
  low: 'text-primary',
  info: 'text-accent',
};

export const StatsCard = ({ title, value, icon: Icon, trend, variant = 'default' }: StatsCardProps) => {
  return (
    <div className={cn(
      "relative p-4 rounded-lg border bg-card terminal-card animate-fade-in",
      variantStyles[variant]
    )}>
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <p className="text-2xl font-bold font-mono">{value}</p>
          {trend && (
            <p className={cn(
              "text-xs font-mono",
              trend.isPositive ? "text-primary" : "text-destructive"
            )}>
              {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}% from last period
            </p>
          )}
        </div>
        <div className={cn(
          "p-2 rounded-md bg-secondary",
          iconVariantStyles[variant]
        )}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
