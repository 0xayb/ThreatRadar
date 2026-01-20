"""AlienVault OTX (Open Threat Exchange) feed collector."""

from typing import List, Optional
import httpx
from datetime import datetime, timedelta
from app.services.base_collector import FeedCollector
from app.models.threat import ThreatIndicator, IOCType


class AlienVaultOTXCollector(FeedCollector):
    """Collector for AlienVault OTX threat intelligence."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("AlienVault OTX", api_key)
        
    def is_configured(self) -> bool:
        """OTX API key is required for full access."""
        return self.api_key is not None
    
    async def fetch_iocs(self, limit: int = 100) -> List[ThreatIndicator]:
        """Fetch recent IOCs from AlienVault OTX."""
        if not self.is_configured():
            self.logger.warning("AlienVault OTX API key not configured, using fallback data")
            return self._generate_fallback_data(limit)
        
        try:
            indicators = []
            
            # Fetch recent pulses (threat intelligence reports)
            headers = {"X-OTX-API-KEY": self.api_key}
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get recent pulses
                response = await client.get(
                    f"{self.BASE_URL}/pulses/subscribed",
                    headers=headers,
                    params={"limit": min(limit // 10, 50)}  # Each pulse has multiple IOCs
                )
                
                if response.status_code != 200:
                    self.logger.error(f"OTX API error: {response.status_code}")
                    return self._generate_fallback_data(limit)
                
                data = response.json()
                
                # Extract IOCs from pulses
                for pulse in data.get("results", [])[:limit // 10]:
                    pulse_indicators = await self._parse_pulse(pulse)
                    indicators.extend(pulse_indicators)
                    
                    if len(indicators) >= limit:
                        break
            
            self.logger.info(f"Fetched {len(indicators)} IOCs from AlienVault OTX")
            return indicators[:limit]
            
        except Exception as e:
            self.logger.error(f"Error fetching from OTX: {str(e)}")
            return self._generate_fallback_data(limit)
    
    async def _parse_pulse(self, pulse: dict) -> List[ThreatIndicator]:
        """Parse indicators from an OTX pulse."""
        indicators = []
        
        # Get pulse metadata
        tags = pulse.get("tags", [])
        description = pulse.get("description", "")
        
        # Determine threat level from tags
        threat_level = "medium"
        if any(tag in tags for tag in ["apt", "ransomware", "critical"]):
            threat_level = "critical"
        elif any(tag in tags for tag in ["malware", "trojan", "exploit"]):
            threat_level = "high"
        
        # Parse each indicator in the pulse
        for indicator_data in pulse.get("indicators", []):
            ioc_type = self._map_otx_type(indicator_data.get("type", ""))
            if not ioc_type:
                continue
                
            value = indicator_data.get("indicator", "")
            if not value:
                continue
            
            # Calculate score from pulse metadata
            score = 70  # Base score
            if pulse.get("adversary"):
                score += 10  # Known adversary
            if len(pulse.get("references", [])) > 0:
                score += 10  # Has references
            if pulse.get("targeted_countries"):
                score += 5  # Targeted attack

            # Adjust threat level based on score to ensure consistency
            final_score = min(score, 100)
            if final_score >= 90:
                # High score should always be critical
                if threat_level not in ["critical"]:
                    threat_level = "critical"
            elif final_score >= 80:
                # High score should be at least high threat
                if threat_level in ["medium", "low", "info"]:
                    threat_level = "high"

            normalized = self.normalize_ioc(
                value=value,
                ioc_type=ioc_type,
                threat_level=threat_level,
                score=final_score,
                tags=tags[:5],  # Limit tags
                description=description[:200] if description else None
            )
            
            if normalized:
                indicators.append(normalized)
        
        return indicators
    
    def _map_otx_type(self, otx_type: str) -> Optional[IOCType]:
        """Map OTX indicator types to our standard IOC types."""
        type_mapping = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash",
            "FileHash-SHA256": "hash",
            "email": "email",
        }
        return type_mapping.get(otx_type)
    
    def _generate_fallback_data(self, limit: int) -> List[ThreatIndicator]:
        """Generate mock data when API key is not available."""
        import random
        
        indicators = []
        tags_pool = ["malware", "phishing", "c2", "ransomware", "apt", "botnet"]
        
        for i in range(min(limit, 20)):
            ioc_type = random.choice(["ip", "domain", "hash", "url"])
            
            if ioc_type == "ip":
                value = f"192.0.2.{random.randint(1, 254)}"  # Use RFC 5737 TEST-NET-1
            elif ioc_type == "domain":
                value = f"malicious-example-{i}.test"  # .test is reserved
            elif ioc_type == "hash":
                value = "a" * 64  # Mock SHA256
            else:
                value = f"https://malicious-example-{i}.test/payload"
            
            threat_level = random.choice(["high", "medium", "low"])
            
            normalized = self.normalize_ioc(
                value=value,
                ioc_type=ioc_type,
                threat_level=threat_level,
                score=random.randint(50, 90),
                tags=[random.choice(tags_pool) for _ in range(2)],
                description=f"[MOCK DATA] Sample {ioc_type} indicator for demonstration"
            )
            
            if normalized:
                indicators.append(normalized)
        
        return indicators
