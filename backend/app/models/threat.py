"""
Data models for threat intelligence indicators and feeds.

This module defines the core data structures used throughout the application
for representing Indicators of Compromise (IOCs), threat feeds, and statistics.
"""

from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, validator
import hashlib


# Type definitions matching frontend expectations
IOCType = Literal["ip", "domain", "hash", "url", "email"]
ThreatLevel = Literal["critical", "high", "medium", "low", "info"]
FeedStatus = Literal["active", "inactive", "error"]


class ThreatIndicator(BaseModel):
    """
    Represents an Indicator of Compromise (IOC) from threat intelligence feeds.
    
    IOCs are artifacts observed on a network or system that indicate a potential
    security breach or malicious activity. Common types include IP addresses,
    domains, file hashes, URLs, and email addresses.
    """
    id: str = Field(default_factory=lambda: hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:12])
    value: str = Field(..., description="The actual IOC value (IP, domain, hash, etc.)")
    type: IOCType = Field(..., description="Type of indicator")
    threat_level: ThreatLevel = Field(..., description="Severity assessment")
    score: int = Field(..., ge=0, le=100, description="Threat score (0-100)")
    sources: List[str] = Field(default_factory=list, description="Feed sources that reported this IOC")
    first_seen: datetime = Field(default_factory=datetime.utcnow, description="First time this IOC was observed")
    last_seen: datetime = Field(default_factory=datetime.utcnow, description="Most recent observation")
    tags: List[str] = Field(default_factory=list, description="Classification tags (malware, phishing, etc.)")
    description: Optional[str] = Field(None, description="Human-readable description")
    correlations: Optional[List[str]] = Field(None, description="IDs of related IOCs")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "abc123def456",
                "value": "192.0.2.1",
                "type": "ip",
                "threat_level": "high",
                "score": 85,
                "sources": ["AlienVault OTX", "AbuseIPDB"],
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-10T00:00:00Z",
                "tags": ["malware", "c2"],
                "description": "C2 server for banking trojan"
            }
        }


class ThreatFeed(BaseModel):
    """
    Represents a threat intelligence feed source.
    
    Feeds aggregate threat data from various security vendors, researchers,
    and automated systems. Each feed has different reliability levels and
    update frequencies.
    """
    id: str
    name: str = Field(..., description="Human-readable feed name")
    description: str = Field(..., description="Feed purpose and coverage")
    url: str = Field(..., description="Feed endpoint or website")
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    indicator_count: int = Field(0, ge=0, description="Number of IOCs from this feed")
    status: FeedStatus = Field("active", description="Current operational status")
    reliability: int = Field(..., ge=1, le=5, description="Feed reliability rating (1-5)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "feed-otx",
                "name": "AlienVault OTX",
                "description": "Open Threat Exchange - Community threat intelligence",
                "url": "https://otx.alienvault.com",
                "last_updated": "2024-01-10T00:00:00Z",
                "indicator_count": 15420,
                "status": "active",
                "reliability": 4
            }
        }


class ThreatStats(BaseModel):
    """
    Aggregate statistics for the threat intelligence database.
    
    Provides quick overview metrics for dashboard display and monitoring.
    """
    total_indicators: int = Field(0, ge=0)
    critical_count: int = Field(0, ge=0)
    high_count: int = Field(0, ge=0)
    medium_count: int = Field(0, ge=0)
    low_count: int = Field(0, ge=0)
    info_count: int = Field(0, ge=0)
    active_feeds: int = Field(0, ge=0)
    correlated_iocs: int = Field(0, ge=0)
    last_24h_new: int = Field(0, ge=0)
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_indicators": 1250,
                "critical_count": 45,
                "high_count": 180,
                "medium_count": 520,
                "low_count": 385,
                "info_count": 120,
                "active_feeds": 4,
                "correlated_iocs": 78,
                "last_24h_new": 23
            }
        }


class FilterOptions(BaseModel):
    """Query parameters for filtering IOCs."""
    search: Optional[str] = None
    types: List[IOCType] = Field(default_factory=list)
    levels: List[ThreatLevel] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class HealthCheck(BaseModel):
    """API health check response."""
    status: str
    timestamp: datetime
    version: str
    feeds_healthy: int
    total_iocs: int
