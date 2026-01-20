"""Threat Intelligence Service - Central coordination for feed collectors."""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio

from app.models.threat import (
    ThreatIndicator,
    ThreatFeed,
    ThreatStats,
    ThreatLevel,
    IOCType,
    FeedStatus
)
from app.services.base_collector import merge_iocs
from app.services.otx_collector import AlienVaultOTXCollector
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ThreatIntelligenceService:
    """Central service for managing threat intelligence data from multiple feeds."""
    
    def __init__(self):
        self.collectors = self._initialize_collectors()
        self.iocs: Dict[str, ThreatIndicator] = {}  # Key: IOC ID
        self.feeds: Dict[str, ThreatFeed] = {}
        self.last_update = datetime.utcnow()
        self._lock = asyncio.Lock()
        
        logger.info(f"Initialized {len(self.collectors)} feed collectors")
    
    def _initialize_collectors(self) -> List:
        """Initialize threat feed collectors."""
        collectors = []

        # AlienVault OTX - Only feed
        otx = AlienVaultOTXCollector(settings.ALIENVAULT_OTX_API_KEY)
        collectors.append(otx)
        logger.info(f"AlienVault OTX: {'configured' if otx.is_configured() else 'using fallback data'}")

        return collectors
    
    async def update_feeds(self) -> None:
        """Fetch latest IOCs from all configured feeds in parallel."""
        async with self._lock:
            logger.info("Starting feed update")
            start_time = datetime.utcnow()
            
            # Fetch from all feeds concurrently
            tasks = []
            for collector in self.collectors:
                task = self._fetch_from_collector(collector)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            new_iocs = {}
            feed_stats = {}
            
            for collector, result in zip(self.collectors, results):
                if isinstance(result, Exception):
                    logger.error(f"Error from {collector.name}: {str(result)}")
                    feed_stats[collector.name] = {
                        "count": 0,
                        "status": "error",
                        "error": str(result)
                    }
                    continue
                
                indicators = result
                feed_stats[collector.name] = {
                    "count": len(indicators),
                    "status": "active",
                    "error": None
                }
                
                # Merge indicators (deduplication)
                for indicator in indicators:
                    if indicator.id in new_iocs:
                        # Merge with existing IOC from another feed
                        new_iocs[indicator.id] = merge_iocs(new_iocs[indicator.id], indicator)
                    else:
                        new_iocs[indicator.id] = indicator
            
            # Update internal state
            self.iocs = new_iocs
            self._update_feed_metadata(feed_stats)
            self.last_update = datetime.utcnow()
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                f"Feed update complete: {len(self.iocs)} unique IOCs from "
                f"{len(self.collectors)} feeds in {duration:.2f}s"
            )
    
    async def _fetch_from_collector(self, collector) -> List[ThreatIndicator]:
        """Wrapper to fetch from a single collector with error handling."""
        try:
            return await collector.fetch_iocs(limit=settings.MAX_IOCS_PER_FEED)
        except Exception as e:
            logger.error(f"Error fetching from {collector.name}: {str(e)}")
            raise
    
    def _update_feed_metadata(self, feed_stats: Dict) -> None:
        """Update feed metadata based on fetch results."""
        for collector in self.collectors:
            stats = feed_stats.get(collector.name, {})
            
            # Map collector to feed ID
            feed_id = f"feed-{collector.name.lower().replace(' ', '-')}"
            
            status: FeedStatus = "active"
            if stats.get("error"):
                status = "error"
            elif stats.get("count", 0) == 0:
                status = "inactive"
            
            # Calculate reliability based on configuration
            reliability = 4  # Default
            if collector.is_configured():
                reliability = 5  # Higher reliability when using real API
            
            self.feeds[feed_id] = ThreatFeed(
                id=feed_id,
                name=collector.name,
                description=self._get_feed_description(collector.name),
                url=self._get_feed_url(collector.name),
                last_updated=datetime.utcnow(),
                indicator_count=stats.get("count", 0),
                status=status,
                reliability=reliability
            )
    
    def _get_feed_description(self, name: str) -> str:
        """Get human-readable feed description."""
        descriptions = {
            "AlienVault OTX": "Open Threat Exchange - Community-driven threat intelligence"
        }
        return descriptions.get(name, f"{name} threat intelligence feed")

    def _get_feed_url(self, name: str) -> str:
        """Get feed homepage URL."""
        urls = {
            "AlienVault OTX": "https://otx.alienvault.com"
        }
        return urls.get(name, "https://example.com")
    
    def get_indicators(
        self,
        search: Optional[str] = None,
        types: Optional[List[IOCType]] = None,
        levels: Optional[List[ThreatLevel]] = None,
        sources: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[ThreatIndicator]:
        """Get filtered and paginated IOCs."""
        results = list(self.iocs.values())
        
        # Apply filters
        if search:
            search_lower = search.lower()
            results = [
                ioc for ioc in results
                if (search_lower in ioc.value.lower() or
                    search_lower in ioc.type.lower() or
                    any(search_lower in tag.lower() for tag in ioc.tags) or
                    any(search_lower in source.lower() for source in ioc.sources))
            ]
        
        if types:
            results = [ioc for ioc in results if ioc.type in types]
        
        if levels:
            results = [ioc for ioc in results if ioc.threat_level in levels]
        
        if sources:
            results = [
                ioc for ioc in results
                if any(source in ioc.sources for source in sources)
            ]
        
        # Sort by threat level (critical first) and score
        threat_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda x: (threat_order[x.threat_level], -x.score))
        
        # Pagination
        return results[offset:offset + limit]
    
    def get_feeds(self) -> List[ThreatFeed]:
        """Get all feed metadata."""
        return list(self.feeds.values())
    
    def get_statistics(self) -> ThreatStats:
        """Calculate aggregate statistics for the dashboard."""
        indicators = list(self.iocs.values())
        
        # Count by threat level
        level_counts = defaultdict(int)
        for ioc in indicators:
            level_counts[ioc.threat_level] += 1
        
        # Count correlated IOCs
        correlated = sum(1 for ioc in indicators if ioc.correlations)
        
        # Count new IOCs in last 24 hours
        day_ago = datetime.utcnow() - timedelta(days=1)
        new_24h = sum(1 for ioc in indicators if ioc.first_seen >= day_ago)
        
        # Count active feeds
        active_feeds = sum(1 for feed in self.feeds.values() if feed.status == "active")
        
        return ThreatStats(
            total_indicators=len(indicators),
            critical_count=level_counts["critical"],
            high_count=level_counts["high"],
            medium_count=level_counts["medium"],
            low_count=level_counts["low"],
            info_count=level_counts["info"],
            active_feeds=active_feeds,
            correlated_iocs=correlated,
            last_24h_new=new_24h
        )
    
    def needs_update(self) -> bool:
        """Check if feeds should be updated based on configured interval."""
        if not self.iocs:  # No data yet
            return True
        
        time_since_update = (datetime.utcnow() - self.last_update).total_seconds()
        return time_since_update >= settings.FEED_UPDATE_INTERVAL


# Global service instance
_service: Optional[ThreatIntelligenceService] = None


def get_threat_service() -> ThreatIntelligenceService:
    """Get or create the global threat intelligence service instance."""
    global _service
    if _service is None:
        _service = ThreatIntelligenceService()
    return _service
