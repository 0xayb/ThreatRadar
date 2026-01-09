#!/usr/bin/env python3
import sys
import json
from datetime import datetime, timezone

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = WHITE = RESET = ""
    class Back:
        RED = GREEN = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""
    COLORS_AVAILABLE = False

from src.feeds.abuseipdb import AbuseIPDBFeed
from src.feeds.urlhaus import URLhausFeed
from src.feeds.threatfox import ThreatFoxFeed
from src.ioc import IOC, IOCType, deduplicate_iocs
from src.scorer import RiskScorer
from src.correlator import IOCCorrelator


def print_banner():
    """Display ASCII banner"""
    banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗         ║
║   ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝         ║
║      ██║   ███████║██████╔╝█████╗  ███████║   ██║            ║
║      ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║            ║
║      ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║            ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝            ║
║                                                              ║
║               ██████╗  █████╗ ██████╗  █████╗ ██████╗        ║
║               ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗       ║
║               ██████╔╝███████║██║  ██║███████║██████╔╝       ║
║               ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗       ║
║               ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║       ║
║               ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝       ║
║                                                              ║
║          Threat Intelligence Aggregation & Analysis          ║
║                   Author : Ayoub Serarfi                     ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def print_menu():
    print("\n" + "="*60)
    print(f"{Fore.CYAN}{Style.BRIGHT}MAIN MENU{Style.RESET_ALL}".center(70))
    print("="*60)
    print()
    print(f"  {Fore.GREEN}[1]{Fore.RESET} Quick Scan - Fetch recent IOCs from all feeds")
    print(f"  {Fore.GREEN}[2]{Fore.RESET} Custom Scan - Choose feeds and IOC types")
    print(f"  {Fore.GREEN}[3]{Fore.RESET} IP Address Lookup - Search specific IP")
    print(f"  {Fore.GREEN}[4]{Fore.RESET} Domain Lookup - Search specific domain")
    print(f"  {Fore.GREEN}[5]{Fore.RESET} Show Feed Status - Check available feeds")
    print(f"  {Fore.GREEN}[6]{Fore.RESET} Export Last Results - Save to JSON")
    print()
    print(f"  {Fore.RED}[0]{Fore.RESET} Exit")
    print()
    print("="*60)


def print_progress(current, total, message=""):
    if total > 0:
        percent = int((current / total) * 100)
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        print(f"\r{Fore.CYAN}[{bar}]{Fore.RESET} {percent}% {message}", end="", flush=True)


def get_risk_color(score):
    if score >= 80:
        return Fore.RED
    elif score >= 60:
        return Fore.YELLOW
    else:
        return Fore.GREEN


def get_available_feeds(config_path='config.yaml'):
    feeds_status = {}
    try:
        feed = AbuseIPDBFeed(config_path)
        feeds_status['abuseipdb'] = 'Available' if feed._get_api_key() else 'No API key'
    except Exception as e:
        feeds_status['abuseipdb'] = f'Error'
    
    feeds_status['urlhaus'] = 'Available'
    feeds_status['threatfox'] = 'Available'
    return feeds_status


def fetch_and_analyze(feeds, limit=50, ioc_type='all', show_progress=True):
    all_iocs = []
    feed_count = len(feeds)
    for idx, (name, feed) in enumerate(feeds.items(), 1):
        try:
            if show_progress:
                print_progress(idx-1, feed_count, f"Fetching {name}...")
            iocs = feed.fetch(limit=limit)
            if ioc_type != 'all':
                iocs = [i for i in iocs if i.ioc_type.value == ioc_type]
            all_iocs.extend(iocs)
            if show_progress:
                print_progress(idx, feed_count, f"✓ {name}: {len(iocs)} IOCs")
        except Exception as e:
            if show_progress:
                print(f"\r{Fore.RED}✗ {name}: {str(e)[:40]}{Fore.RESET}")
    if show_progress:
        print()
    if not all_iocs:
        return None, None, None
    original_count = len(all_iocs)
    all_iocs = deduplicate_iocs(all_iocs)
    print(f"{Fore.CYAN}Deduplicated: {original_count} → {len(all_iocs)} unique IOCs{Fore.RESET}")
    correlator = IOCCorrelator()
    correlations = correlator.correlate(all_iocs)
    scorer = RiskScorer()
    scored_iocs = [(ioc, *scorer.score(ioc, correlations)) for ioc in all_iocs]
    scored_iocs.sort(key=lambda x: x[1], reverse=True)
    return scored_iocs, correlations, all_iocs


def display_results(scored_iocs, max_results=10, show_details=False):
    print("\n" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT}TOP {max_results} HIGH-RISK IOCs{Style.RESET_ALL}".center(90))
    print("="*80)
    for i, (ioc, score, details) in enumerate(scored_iocs[:max_results], 1):
        age = (datetime.now(timezone.utc) - ioc.first_seen).total_seconds()
        if age < 3600:
            age_str = f"{int(age/60)}m ago"
        elif age < 86400:
            age_str = f"{int(age/3600)}h ago"
        else:
            age_str = f"{int(age/86400)}d ago"
        indicator = ioc.value[:50] + "..." if len(ioc.value) > 53 else ioc.value
        risk_color = get_risk_color(score)
        print(f"\n{Fore.WHITE}{i:2}.{Fore.RESET} {risk_color}[{score:3}]{Fore.RESET} {Style.BRIGHT}{indicator}{Style.RESET_ALL}")
        print(f"    Type: {Fore.CYAN}{ioc.ioc_type.value.upper():8}{Fore.RESET} | "
              f"Feeds: {Fore.YELLOW}{details['feed_count']}{Fore.RESET} | "
              f"Age: {Fore.GREEN}{age_str}{Fore.RESET}")
        if ioc.tags:
            tags_str = ', '.join(ioc.tags[:3])
            print(f"    Tags: {Fore.MAGENTA}{tags_str}{Fore.RESET}")
        if show_details:
            print(f"    Score breakdown: Recency={details['recency_score']:.0f} | "
                  f"Severity={details['severity_score']:.0f} | "
                  f"Correlation=+{details['correlation_bonus']}")
    
    print("\n" + "="*80)


def quick_scan():
    print("\n" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT}QUICK SCAN{Style.RESET_ALL}".center(90))
    print("="*80)
    limit = input(f"\n{Fore.YELLOW}Number of IOCs per feed (default 50):{Fore.RESET} ").strip() or "50"
    try:
        limit = int(limit)
    except ValueError:
        print(f"{Fore.RED}Invalid number, using 50{Fore.RESET}")
        limit = 50
    show_details = input(f"{Fore.YELLOW}Show detailed scoring breakdown? (y/N):{Fore.RESET} ").strip().lower() == 'y'
    print(f"\n{Fore.CYAN}Fetching {limit} IOCs from all feeds...{Fore.RESET}\n")
    feeds = {
        'abuseipdb': AbuseIPDBFeed('config.yaml'),
        'urlhaus': URLhausFeed('config.yaml'),
        'threatfox': ThreatFoxFeed('config.yaml')
    }
    global last_results
    last_results = fetch_and_analyze(feeds, limit=limit, show_progress=True)
    if last_results[0] is None:
        print(f"\n{Fore.RED}⚠ No IOCs retrieved{Fore.RESET}")
        return
    scored_iocs, correlations, all_iocs = last_results
    print(f"\n{Fore.GREEN}✓ Analysis complete!{Fore.RESET}")
    print(f"  Total IOCs: {len(all_iocs)}")
    single_feed = sum(1 for _, _, d in scored_iocs if d['feed_count'] == 1)
    multi_feed = len(all_iocs) - single_feed
    print(f"  Single feed: {single_feed} | Multi-feed: {Fore.YELLOW}{multi_feed}{Fore.RESET}")
    display_results(scored_iocs, max_results=10, show_details=show_details)


def custom_scan():
    print("\n" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT}CUSTOM SCAN{Style.RESET_ALL}".center(90))
    print("="*80)
    print(f"\n{Fore.YELLOW}Available feeds:{Fore.RESET}")
    print(f"  {Fore.GREEN}[1]{Fore.RESET} AbuseIPDB (malicious IPs)")
    print(f"  {Fore.GREEN}[2]{Fore.RESET} URLhaus (malware URLs)")
    print(f"  {Fore.GREEN}[3]{Fore.RESET} ThreatFox (malware hashes)")
    print(f"  {Fore.GREEN}[4]{Fore.RESET} All feeds") 
    choice = input(f"\n{Fore.YELLOW}Select feeds (1-4):{Fore.RESET} ").strip()
    feed_map = {
        '1': {'abuseipdb': AbuseIPDBFeed},
        '2': {'urlhaus': URLhausFeed},
        '3': {'threatfox': ThreatFoxFeed},
        '4': {'abuseipdb': AbuseIPDBFeed, 'urlhaus': URLhausFeed, 'threatfox': ThreatFoxFeed}
    }
    selected_feeds = feed_map.get(choice, feed_map['4'])
    print(f"\n{Fore.YELLOW}IOC types:{Fore.RESET}")
    print(f"  {Fore.GREEN}[1]{Fore.RESET} IP addresses")
    print(f"  {Fore.GREEN}[2]{Fore.RESET} Domains")
    print(f"  {Fore.GREEN}[3]{Fore.RESET} URLs")
    print(f"  {Fore.GREEN}[4]{Fore.RESET} Hashes")
    print(f"  {Fore.GREEN}[5]{Fore.RESET} All types")
    type_choice = input(f"\n{Fore.YELLOW}Select IOC type (1-5):{Fore.RESET} ").strip()
    type_map = {'1': 'ip', '2': 'domain', '3': 'url', '4': 'hash', '5': 'all'}
    ioc_type = type_map.get(type_choice, 'all')
    limit = input(f"\n{Fore.YELLOW}Max IOCs per feed (default 100):{Fore.RESET} ").strip() or "100"
    try:
        limit = int(limit)
    except ValueError:
        limit = 100
    show_details = input(f"{Fore.YELLOW}Show detailed scoring? (y/N):{Fore.RESET} ").strip().lower() == 'y'
    print(f"\n{Fore.CYAN}Scanning for {ioc_type.upper()} IOCs...{Fore.RESET}\n")
    feeds = {name: cls('config.yaml') for name, cls in selected_feeds.items()}
    global last_results
    last_results = fetch_and_analyze(feeds, limit=limit, ioc_type=ioc_type, show_progress=True)
    if last_results[0] is None:
        print(f"\n{Fore.RED}⚠ No IOCs retrieved{Fore.RESET}")
        return
    scored_iocs, _, all_iocs = last_results
    print(f"\n{Fore.GREEN}✓ Scan complete! Total unique IOCs: {len(all_iocs)}{Fore.RESET}")
    display_results(scored_iocs, max_results=15, show_details=show_details)


def ip_lookup():
    print("\n" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT}IP ADDRESS LOOKUP{Style.RESET_ALL}".center(90))
    print("="*80)
    ip = input(f"\n{Fore.YELLOW}Enter IP address:{Fore.RESET} ").strip()
    if not ip:
        print(f"{Fore.RED}No IP provided{Fore.RESET}")
        return
    print(f"\n{Fore.CYAN}Searching for {ip} in all feeds...{Fore.RESET}\n")
    feeds = {
        'abuseipdb': AbuseIPDBFeed('config.yaml'),
        'urlhaus': URLhausFeed('config.yaml'),
        'threatfox': ThreatFoxFeed('config.yaml')
    }
    all_iocs = []
    for name, feed in feeds.items():
        try:
            print(f"  → Checking {name}...", end="", flush=True)
            iocs = feed.fetch(limit=500)
            matching = [i for i in iocs if i.ioc_type == IOCType.IP and i.value == ip]
            all_iocs.extend(matching)
            print(f" {Fore.GREEN}✓{Fore.RESET} ({len(matching)} matches)")
        except Exception as e:
            print(f" {Fore.RED}✗ Error{Fore.RESET}")
    if not all_iocs:
        print(f"\n{Fore.YELLOW}⚠ IP not found in any feed{Fore.RESET}")
        print(f"This could mean:")
        print(f"  • IP is not currently flagged as malicious")
        print(f"  • IP is too old (feeds show recent data)")
        print(f"  • IP has not been reported yet")
        return
    all_iocs = deduplicate_iocs(all_iocs)
    correlator = IOCCorrelator()
    correlations = correlator.correlate(all_iocs)
    scorer = RiskScorer()
    scored_iocs = [(ioc, *scorer.score(ioc, correlations)) for ioc in all_iocs]
    print(f"\n{Fore.RED}⚠ THREAT DETECTED{Fore.RESET}")
    print("="*80)
    for ioc, score, details in scored_iocs:
        risk_color = get_risk_color(score)
        print(f"\n{risk_color}Risk Score: {score}/100{Fore.RESET}")
        print(f"Reported by: {Fore.YELLOW}{details['feed_count']}{Fore.RESET} feed(s)")
        print(f"Confidence: {details['severity_score']:.0f}/100")
        print(f"First seen: {ioc.first_seen.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        if ioc.tags:
            print(f"Threat tags: {Fore.MAGENTA}{', '.join(ioc.tags)}{Fore.RESET}")
        if ioc.metadata.get('sources'):
            print(f"Sources: {', '.join(ioc.metadata['sources'])}")


def domain_lookup():
    print("\n" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT}DOMAIN LOOKUP{Style.RESET_ALL}".center(90))
    print("="*80)
    domain = input(f"\n{Fore.YELLOW}Enter domain:{Fore.RESET} ").strip().lower()
    if not domain:
        print(f"{Fore.RED}No domain provided{Fore.RESET}")
        return
    print(f"\n{Fore.CYAN}Searching for {domain} in all feeds...{Fore.RESET}\n")
    feeds = {
        'urlhaus': URLhausFeed('config.yaml'),
        'threatfox': ThreatFoxFeed('config.yaml')
    }
    all_iocs = []
    for name, feed in feeds.items():
        try:
            print(f"  → Checking {name}...", end="", flush=True)
            iocs = feed.fetch(limit=500)
            matching = [i for i in iocs if i.ioc_type == IOCType.DOMAIN and 
                       (i.value == domain or i.normalized_value == domain.removeprefix('www.'))]
            all_iocs.extend(matching)
            print(f" {Fore.GREEN}✓{Fore.RESET} ({len(matching)} matches)")
        except Exception as e:
            print(f" {Fore.RED}✗ Error{Fore.RESET}")
    if not all_iocs:
        print(f"\n{Fore.YELLOW}⚠ Domain not found in any feed{Fore.RESET}")
        return
    all_iocs = deduplicate_iocs(all_iocs)
    correlator = IOCCorrelator()
    correlations = correlator.correlate(all_iocs)
    scorer = RiskScorer()
    scored_iocs = [(ioc, *scorer.score(ioc, correlations)) for ioc in all_iocs]
    print(f"\n{Fore.RED}⚠ THREAT DETECTED{Fore.RESET}")
    print("="*80)
    for ioc, score, details in scored_iocs:
        risk_color = get_risk_color(score)
        print(f"\n{risk_color}Risk Score: {score}/100{Fore.RESET}")
        print(f"Reported by: {Fore.YELLOW}{details['feed_count']}{Fore.RESET} feed(s)")
        print(f"First seen: {ioc.first_seen.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        if ioc.tags:
            print(f"Threat type: {Fore.MAGENTA}{', '.join(ioc.tags)}{Fore.RESET}")


def feed_status():
    print("\n" + "="*80)
    print(f"{Fore.CYAN}{Style.BRIGHT}FEED STATUS{Style.RESET_ALL}".center(90))
    print("="*80)
    status = get_available_feeds()
    print(f"\n{'Feed':<20} {'Status'}")
    print("-" * 80)
    for feed, stat in status.items():
        if "Available" in stat:
            symbol = f"{Fore.GREEN}✓{Fore.RESET}"
            color = Fore.GREEN
        else:
            symbol = f"{Fore.RED}✗{Fore.RESET}"
            color = Fore.RED
        print(f"{symbol} {feed:<18} {color}{stat}{Fore.RESET}")


def export_results():
    global last_results
    if last_results is None or last_results[0] is None:
        print(f"\n{Fore.RED}⚠ No results to export. Run a scan first!{Fore.RESET}")
        return
    filename = input(f"\n{Fore.YELLOW}Filename (default: results.json):{Fore.RESET} ").strip() or "results.json"
    if not filename.endswith('.json'):
        filename += '.json'
    scored_iocs, correlations, all_iocs = last_results
    output_data = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_iocs': len(scored_iocs),
        'iocs': [
            {
                'indicator': ioc.value,
                'type': ioc.ioc_type.value,
                'score': score,
                'source': ioc.source,
                'first_seen': ioc.first_seen.isoformat(),
                'confidence': ioc.confidence,
                'tags': ioc.tags,
                'feed_count': details['feed_count'],
                'scoring_details': {
                    'recency': details['recency_score'],
                    'severity': details['severity_score'],
                    'correlation_bonus': details['correlation_bonus']
                }
            }
            for ioc, score, details in scored_iocs
        ]
    }
    try:
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n{Fore.GREEN}✓ Results saved to {filename}{Fore.RESET}")
        print(f"  Total IOCs: {len(scored_iocs)}")
    except Exception as e:
        print(f"\n{Fore.RED}✗ Export failed: {e}{Fore.RESET}")


last_results = None


def main():
    print_banner()
    if not COLORS_AVAILABLE:
        print("\n⚠ Note: Install 'colorama' for colored output: pip install colorama\n")
    while True:
        print_menu()
        choice = input(f"{Fore.YELLOW}Select option:{Fore.RESET} ").strip()
        try:
            if choice == '1':
                quick_scan()
            elif choice == '2':
                custom_scan()
            elif choice == '3':
                ip_lookup()
            elif choice == '4':
                domain_lookup()
            elif choice == '5':
                feed_status()
            elif choice == '6':
                export_results()
            elif choice == '0':
                print(f"\n{Fore.CYAN}👋 Thanks for using Threat Radar!{Fore.RESET}")
                sys.exit(0)
            else:
                print(f"\n{Fore.RED}⚠ Invalid option{Fore.RESET}")
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}Operation cancelled{Fore.RESET}")
        except Exception as e:
            print(f"\n{Fore.RED}✗ Error: {e}{Fore.RESET}")
        input(f"\n{Fore.CYAN}Press Enter to continue...{Fore.RESET}")


if __name__ == '__main__':
    main()