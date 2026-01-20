"""
API Routes for Threat Intelligence.

This module defines all REST API endpoints that the frontend uses to:
- Fetch IOCs with filtering
- Get feed status
- Retrieve statistics
- Check system health
"""

from typing import List, Optional
from fastapi import APIRouter, Query, BackgroundTasks, HTTPException
from datetime import datetime

from app.models.threat import (
    ThreatIndicator,
    ThreatFeed,
    ThreatStats,
    IOCType,
    ThreatLevel,
    HealthCheck
)
from app.services.threat_service import get_threat_service
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/health", response_model=HealthCheck)
async def health_check():
    """
    Health check endpoint.
    
    Returns system status and basic metrics. Useful for monitoring
    and ensuring the API is operational.
    """
    service = get_threat_service()
    stats = service.get_statistics()
    feeds = service.get_feeds()
    
    feeds_healthy = sum(1 for feed in feeds if feed.status == "active")
    
    return HealthCheck(
        status="healthy",
        timestamp=datetime.utcnow(),
        version=settings.APP_VERSION,
        feeds_healthy=feeds_healthy,
        total_iocs=stats.total_indicators
    )


@router.get("/indicators", response_model=List[ThreatIndicator])
async def get_indicators(
    background_tasks: BackgroundTasks,
    search: Optional[str] = Query(None, description="Search term for filtering IOCs"),
    types: Optional[List[IOCType]] = Query(None, description="Filter by IOC types"),
    levels: Optional[List[ThreatLevel]] = Query(None, description="Filter by threat levels"),
    sources: Optional[List[str]] = Query(None, description="Filter by feed sources"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Pagination offset")
):
    """
    Get threat indicators with optional filtering.
    
    This is the main endpoint used by the dashboard to display IOCs.
    Supports:
    - Full-text search across IOC values, types, and tags
    - Filtering by IOC type (ip, domain, hash, url, email)
    - Filtering by threat level (critical, high, medium, low, info)
    - Filtering by source feed
    - Pagination
    
    Educational Note:
    The background task pattern allows us to refresh feeds asynchronously
    without blocking the API response. This ensures fast response times
    while keeping data fresh.
    """
    service = get_threat_service()
    
    # Trigger feed update in background if needed
    if service.needs_update():
        background_tasks.add_task(service.update_feeds)
        logger.info("Scheduled background feed update")
    
    # Get filtered indicators
    indicators = service.get_indicators(
        search=search,
        types=types or [],
        levels=levels or [],
        sources=sources or [],
        limit=limit,
        offset=offset
    )
    
    logger.info(
        f"Retrieved {len(indicators)} indicators "
        f"(search={search}, types={types}, levels={levels}, sources={sources})"
    )
    
    return indicators


@router.get("/feeds", response_model=List[ThreatFeed])
async def get_feeds():
    """
    Get metadata for all threat intelligence feeds.
    
    Returns information about each configured feed including:
    - Current status (active, inactive, error)
    - Last update time
    - Number of IOCs contributed
    - Reliability rating
    """
    service = get_threat_service()
    feeds = service.get_feeds()
    
    logger.info(f"Retrieved {len(feeds)} feed statuses")
    return feeds


@router.get("/statistics", response_model=ThreatStats)
async def get_statistics():
    """
    Get aggregate threat intelligence statistics.
    
    Provides dashboard metrics including:
    - Total IOC count
    - Breakdown by threat level
    - Active feed count
    - Correlation metrics
    - New IOCs in last 24 hours
    """
    service = get_threat_service()
    stats = service.get_statistics()
    
    logger.info(f"Retrieved statistics: {stats.total_indicators} total IOCs")
    return stats


@router.post("/feeds/update")
async def trigger_feed_update(background_tasks: BackgroundTasks):
    """
    Manually trigger a feed update.
    
    Useful for administrators who want to force a refresh
    without waiting for the automatic update interval.
    
    Educational Note:
    This demonstrates how to give users control over background
    processes through API endpoints. Important for testing and
    troubleshooting in academic environments.
    """
    service = get_threat_service()
    
    # Add update task to background
    background_tasks.add_task(service.update_feeds)
    
    logger.info("Manual feed update triggered")
    return {
        "status": "success",
        "message": "Feed update scheduled in background",
        "timestamp": datetime.utcnow()
    }


@router.get("/indicators/{ioc_id}", response_model=ThreatIndicator)
async def get_indicator_by_id(ioc_id: str):
    """
    Get detailed information about a specific IOC.
    
    Useful for drilling down into a specific indicator to see:
    - All sources that reported it
    - Complete tag list
    - Correlation information
    - Full description
    """
    service = get_threat_service()
    
    if ioc_id not in service.iocs:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    indicator = service.iocs[ioc_id]
    logger.info(f"Retrieved indicator {ioc_id}")
    
    return indicator
