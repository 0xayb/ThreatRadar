import { useState } from 'react';
import { Search, Filter, X } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { IOCType, ThreatLevel } from '@/types/threat';

interface SearchFilterProps {
  onSearchChange: (search: string) => void;
  onTypeFilter: (types: IOCType[]) => void;
  onLevelFilter: (levels: ThreatLevel[]) => void;
  selectedTypes: IOCType[];
  selectedLevels: ThreatLevel[];
}

const iocTypes: IOCType[] = ['ip', 'domain', 'hash', 'url', 'email'];
const threatLevels: ThreatLevel[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SearchFilter = ({
  onSearchChange,
  onTypeFilter,
  onLevelFilter,
  selectedTypes,
  selectedLevels,
}: SearchFilterProps) => {
  const [showFilters, setShowFilters] = useState(false);

  const toggleType = (type: IOCType) => {
    if (selectedTypes.includes(type)) {
      onTypeFilter(selectedTypes.filter(t => t !== type));
    } else {
      onTypeFilter([...selectedTypes, type]);
    }
  };

  const toggleLevel = (level: ThreatLevel) => {
    if (selectedLevels.includes(level)) {
      onLevelFilter(selectedLevels.filter(l => l !== level));
    } else {
      onLevelFilter([...selectedLevels, level]);
    }
  };

  const clearFilters = () => {
    onTypeFilter([]);
    onLevelFilter([]);
  };

  const hasActiveFilters = selectedTypes.length > 0 || selectedLevels.length > 0;

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search IOCs by value, type, or tag..."
            className="pl-10 font-mono bg-secondary border-border focus:border-primary"
            onChange={(e) => onSearchChange(e.target.value)}
          />
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`px-4 py-2 rounded-md border transition-colors flex items-center gap-2 ${
            showFilters || hasActiveFilters
              ? 'border-primary bg-primary/10 text-primary'
              : 'border-border bg-secondary text-muted-foreground hover:text-foreground'
          }`}
        >
          <Filter className="w-4 h-4" />
          <span className="text-sm font-mono">Filter</span>
          {hasActiveFilters && (
            <span className="w-5 h-5 rounded-full bg-primary text-primary-foreground text-xs flex items-center justify-center">
              {selectedTypes.length + selectedLevels.length}
            </span>
          )}
        </button>
      </div>

      {showFilters && (
        <div className="p-4 rounded-lg border border-border bg-card animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-muted-foreground">Filters</span>
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="text-xs text-muted-foreground hover:text-destructive transition-colors flex items-center gap-1"
              >
                <X className="w-3 h-3" />
                Clear all
              </button>
            )}
          </div>

          <div className="space-y-3">
            <div>
              <p className="text-xs text-muted-foreground mb-2">IOC Type</p>
              <div className="flex flex-wrap gap-2">
                {iocTypes.map((type) => (
                  <button
                    key={type}
                    onClick={() => toggleType(type)}
                    className={`transition-all ${selectedTypes.includes(type) ? 'ring-2 ring-primary' : ''}`}
                  >
                    <Badge variant={type} className="cursor-pointer">
                      {type.toUpperCase()}
                    </Badge>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs text-muted-foreground mb-2">Threat Level</p>
              <div className="flex flex-wrap gap-2">
                {threatLevels.map((level) => (
                  <button
                    key={level}
                    onClick={() => toggleLevel(level)}
                    className={`transition-all ${selectedLevels.includes(level) ? 'ring-2 ring-primary' : ''}`}
                  >
                    <Badge variant={level} className="cursor-pointer capitalize">
                      {level}
                    </Badge>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
