"""
Base class and utilities for threat intelligence feed collectors.

Each feed collector implements a standardized interface for fetching,
parsing, and normalizing IOCs from different threat intelligence sources.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime
import hashlib
import re
import ipaddress
from app.models.threat import ThreatIndicator, IOCType, ThreatLevel
from app.core.logging import get_logger

logger = get_logger(__name__)


class FeedCollector(ABC):
    """
    Abstract base class for all threat feed collectors.
    
    Provides common functionality for:
    - Data fetching
    - IOC normalization
    - Error handling
    - Rate limiting awareness
    """
    
    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key
        self.logger = get_logger(f"collector.{name.lower().replace(' ', '_')}")
        
    @abstractmethod
    async def fetch_iocs(self, limit: int = 100) -> List[ThreatIndicator]:
        """
        Fetch IOCs from the threat feed.
        
        Args:
            limit: Maximum number of IOCs to fetch
            
        Returns:
            List of normalized ThreatIndicator objects
        """
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the feed has necessary API keys/configuration."""
        pass
    
    def normalize_ioc(
        self,
        value: str,
        ioc_type: IOCType,
        threat_level: Optional[ThreatLevel] = None,
        score: Optional[int] = None,
        tags: Optional[List[str]] = None,
        description: Optional[str] = None
    ) -> Optional[ThreatIndicator]:
        """
        Normalize and validate an IOC.
        
        This is a critical security function - it ensures that IOCs are
        properly formatted and validated before entering the database.
        Invalid IOCs could indicate data corruption or feed compromise.
        """
        try:
            # Clean and validate the value
            value = value.strip().lower()
            
            # Type-specific validation
            if ioc_type == "ip":
                # Validate IP address format
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    self.logger.warning(f"Invalid IP address: {value}")
                    return None
                    
            elif ioc_type == "domain":
                # Basic domain validation
                if not re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', value):
                    self.logger.warning(f"Invalid domain: {value}")
                    return None
                    
            elif ioc_type == "hash":
                # Validate hash format (MD5, SHA1, SHA256)
                if not re.match(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', value):
                    self.logger.warning(f"Invalid hash: {value}")
                    return None
                    
            elif ioc_type == "url":
                # Basic URL validation
                if not re.match(r'^https?://', value):
                    self.logger.warning(f"Invalid URL: {value}")
                    return None
                    
            elif ioc_type == "email":
                # Basic email validation
                if not re.match(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$', value):
                    self.logger.warning(f"Invalid email: {value}")
                    return None
            
            # Generate deterministic ID based on value and type
            # This ensures the same IOC always gets the same ID for deduplication
            ioc_id = hashlib.md5(f"{ioc_type}:{value}".encode()).hexdigest()[:12]
            
            # Auto-determine threat level from score if not provided
            if not threat_level and score is not None:
                if score >= 90:
                    threat_level = "critical"
                elif score >= 70:
                    threat_level = "high"
                elif score >= 50:
                    threat_level = "medium"
                elif score >= 30:
                    threat_level = "low"
                else:
                    threat_level = "info"
            
            # Default values
            threat_level = threat_level or "medium"
            score = score or 50
            tags = tags or []
            
            return ThreatIndicator(
                id=ioc_id,
                value=value,
                type=ioc_type,
                threat_level=threat_level,
                score=score,
                sources=[self.name],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                tags=tags,
                description=description or f"{ioc_type.upper()} indicator from {self.name}"
            )
            
        except Exception as e:
            self.logger.error(f"Error normalizing IOC {value}: {str(e)}")
            return None


def merge_iocs(existing: ThreatIndicator, new: ThreatIndicator) -> ThreatIndicator:
    """
    Merge two IOC records for the same indicator from different sources.
    
    This is important for correlation - when multiple feeds report the same
    IOC, it increases confidence in the indicator. The merged record combines
    sources, updates timestamps, and adjusts the threat score.
    """
    # Merge sources (deduplicated)
    sources = list(set(existing.sources + new.sources))
    
    # Take the higher threat level
    threat_levels = ["info", "low", "medium", "high", "critical"]
    existing_level_idx = threat_levels.index(existing.threat_level)
    new_level_idx = threat_levels.index(new.threat_level)
    threat_level = threat_levels[max(existing_level_idx, new_level_idx)]
    
    # Average the scores, but weight by number of sources
    # More sources = higher confidence = higher score
    base_score = (existing.score + new.score) / 2
    source_boost = min(len(sources) * 5, 20)  # Up to +20 for multiple sources
    score = min(100, int(base_score + source_boost))
    
    # Merge tags
    tags = list(set(existing.tags + new.tags))
    
    # Use earliest first_seen and latest last_seen
    first_seen = min(existing.first_seen, new.first_seen)
    last_seen = max(existing.last_seen, new.last_seen)
    
    return ThreatIndicator(
        id=existing.id,
        value=existing.value,
        type=existing.type,
        threat_level=threat_level,
        score=score,
        sources=sources,
        first_seen=first_seen,
        last_seen=last_seen,
        tags=tags,
        description=existing.description or new.description
    )
