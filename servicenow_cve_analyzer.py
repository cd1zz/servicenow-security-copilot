#!/usr/bin/env python3
"""
ServiceNow CVE Analyzer
Main goal: Find how many systems are vulnerable to a specific CVE
Secondary: List system names and IPs (with exports for full lists)
"""

import requests
import json
import sys
import os
from typing import Dict, List, Optional
from urllib.parse import urljoin
import time
import argparse
from collections import defaultdict


class ServiceNowCVEAnalyzer:
    def __init__(self, instance_url: str, client_id: str, client_secret: str, 
                 username: str, password: str):
        """Initialize ServiceNow client with OAuth2 credentials."""
        self.instance_url = instance_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.token_expiry = 0
        
    def get_oauth_token(self) -> str:
        """Get OAuth2 access token."""
        if self.access_token and time.time() < self.token_expiry:
            return self.access_token
            
        token_url = f"{self.instance_url}/oauth_token.do"
        
        data = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.username,
            'password': self.password
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            response = requests.post(token_url, data=data, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"❌ Authentication failed: {e}")
            sys.exit(1)
        
        token_data = response.json()
        self.access_token = token_data['access_token']
        self.token_expiry = time.time() + token_data.get('expires_in', 1800) - 300
        
        return self.access_token
    
    def api_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make authenticated API request."""
        token = self.get_oauth_token()
        url = urljoin(self.instance_url, endpoint)
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 400:
                return None
            response.raise_for_status()
            return response.json()
        except:
            return None
    
    def analyze_cve(self, cve_id: str, fetch_all_details: bool = False, include_patched: bool = False) -> Dict:
        """
        Main function: Analyze CVE and count vulnerable systems.
        
        Args:
            cve_id: CVE identifier
            fetch_all_details: If True, fetch details for all systems (slower)
                              If False, use counts from metadata and fetch sample (faster)
        """
        print(f"\n{'=' * 80}")
        print(f"🔍 ANALYZING {cve_id}")
        print(f"{'=' * 80}")
        
        results = {
            'cve_id': cve_id,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'found': False,
            'total_vulnerable_systems': 0,
            'systems': []
        }
        
        # Step 1: Find CVE in NVD entries
        print(f"\nSearching for {cve_id}...")
        params = {
            'sysparm_query': f'id={cve_id}',
            'sysparm_limit': '1'
        }
        
        nvd_result = self.api_request('/api/now/table/sn_vul_nvd_entry', params)
        if not nvd_result or not nvd_result.get('result'):
            print(f"❌ CVE not found in ServiceNow")
            return results
        
        nvd_entry = nvd_result['result'][0]
        results['found'] = True
        results['cvss_score'] = nvd_entry.get('v3_base_score', 'N/A')
        results['summary'] = nvd_entry.get('summary', 'N/A')
        results['published'] = str(nvd_entry.get('date_published', 'N/A'))
        
        print(f"✅ Found CVE - CVSS Score: {results['cvss_score']}")
        
        # Step 2: Find third-party entries to get TOTAL COUNT
        cve_sys_id = nvd_entry.get('sys_id')
        params = {
            'sysparm_query': f'cves_listLIKE{cve_sys_id}',
            'sysparm_limit': '100'
        }
        
        third_party_result = self.api_request('/api/now/table/sn_vul_third_party_entry', params)
        
        if not third_party_result or not third_party_result.get('result'):
            print("No vulnerability scan data found")
            return results
        
        third_party_entries = third_party_result['result']
        
        # Calculate TOTAL from scanner metadata
        total_active = sum(int(tp.get('count_active_vi', 0)) for tp in third_party_entries)
        total_all_time = sum(int(tp.get('total_vis', 0)) for tp in third_party_entries)
        
        results['total_vulnerable_systems'] = total_active
        results['total_all_time'] = total_all_time
        
        print(f"\n📊 VULNERABILITY COUNTS:")
        print(f"   Currently Vulnerable (Active): {total_active}")
        print(f"   All-Time Total (Inc. Patched): {total_all_time}")
        
        # Show breakdown by source
        for tp in third_party_entries:
            source = tp.get('source', 'Unknown')
            qid = tp.get('id', 'N/A')
            active = int(tp.get('count_active_vi', 0))
            total = int(tp.get('total_vis', 0))
            print(f"   • {source} {qid}: {active} active / {total} total")
        
        # Step 3: Get system details (full or sample based on count and preference)
        if total_active == 0:
            print("No vulnerable systems found")
            return results
        
        print(f"\nRetrieving system details...")
        
        # Decide how many details to fetch
        if fetch_all_details or total_active <= 100:
            # Fetch all if requested or if count is reasonable
            limit_per_query = min(1000, total_active)
            sample_only = False
        else:
            # Fetch sample for performance
            limit_per_query = 50
            sample_only = True
        
        systems = []
        seen_systems = set()
        
        for tp in third_party_entries:
            tp_sys_id = tp.get('sys_id')
            
            # Get vulnerable items - filter by active status
            if include_patched:
                query = f'vulnerability={tp_sys_id}'  # Get all
            else:
                query = f'vulnerability={tp_sys_id}^active=true'  # Only currently vulnerable
            
            params = {
                'sysparm_query': query,
                'sysparm_limit': str(limit_per_query),
                'sysparm_fields': 'sys_id,number,cmdb_ci,short_description,active,state'
            }
            
            vi_result = self.api_request('/api/now/table/sn_vul_vulnerable_item', params)
            
            if vi_result and vi_result.get('result'):
                for vi in vi_result['result']:
                    ci_ref = vi.get('cmdb_ci', {})
                    
                    if isinstance(ci_ref, dict) and ci_ref.get('value'):
                        ci_id = ci_ref['value']
                        
                        if ci_id not in seen_systems:
                            seen_systems.add(ci_id)
                            
                            # Get CI details
                            ci_result = self.api_request(f'/api/now/table/cmdb_ci/{ci_id}')
                            
                            if ci_result and ci_result.get('result'):
                                ci = ci_result['result']
                                systems.append({
                                    'name': ci.get('name', 'Unknown'),
                                    'ip_address': ci.get('ip_address', 'N/A'),
                                    'type': ci.get('sys_class_name', 'Unknown'),
                                    'status': ci.get('operational_status', ''),
                                    'vi_number': vi.get('number', ''),
                                    'description': vi.get('short_description', '')
                                })
                            
                            # Stop if we have enough for sample
                            if sample_only and len(systems) >= limit_per_query:
                                break
        
        results['systems'] = systems
        results['systems_retrieved'] = len(systems)
        results['sample_only'] = sample_only
        
        return results
    
    def display_results(self, results: Dict):
        """Display results with focus on TOTAL COUNT."""
        if not results['found']:
            return
        
        print(f"\n{'=' * 80}")
        print(f"📊 RESULTS for {results['cve_id']}")
        print(f"{'=' * 80}")
        
        # The most important information - TOTAL COUNT
        total = results['total_vulnerable_systems']
        
        print(f"\n🔴 TOTAL VULNERABLE SYSTEMS: {total}\n")
        
        print(f"CVSS Score: {results['cvss_score']}")
        print(f"Published: {results['published']}")
        
        # Show systems list
        systems = results['systems']
        retrieved = results['systems_retrieved']
        
        if systems:
            if results['sample_only']:
                print(f"\n📋 SAMPLE SYSTEMS (showing {min(10, len(systems))} of {total}):")
            else:
                print(f"\n📋 VULNERABLE SYSTEMS (showing {min(10, len(systems))} of {retrieved}):")
            
            print("-" * 60)
            
            # Show first 10 systems
            for i, system in enumerate(sorted(systems, key=lambda x: x['name'])[:10], 1):
                print(f"\n{i}. {system['name']}")
                print(f"   IP: {system['ip_address']}")
                if system['description']:
                    print(f"   Issue: {system['description'][:60]}")
            
            if len(systems) > 10:
                print(f"\n... and {len(systems) - 10} more in export files")
        
        # Summary message
        if results['sample_only']:
            print(f"\n💡 Retrieved details for {retrieved} systems (sample)")
            print(f"   Full enumeration would require fetching {total} records")
        
        print(f"\n📁 Files exported:")
        print(f"   • CSV with system list")
        print(f"   • JSON with full details")
        print(f"   • TXT summary report")
    
    def export_results(self, results: Dict):
        """Export results to files."""
        if not results['found']:
            return
            
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        cve_clean = results['cve_id'].replace('/', '_')
        
        # CSV - System list
        csv_file = f'{cve_clean}_systems_{timestamp}.csv'
        with open(csv_file, 'w') as f:
            f.write('System Name,IP Address,Type,Status,Issue\n')
            for system in sorted(results['systems'], key=lambda x: x['name']):
                f.write(f'"{system["name"]}","{system["ip_address"]}",')
                f.write(f'"{system["type"]}","{system["status"]}",')
                f.write(f'"{system["description"]}"\n')
        
        # JSON - Full data
        json_file = f'{cve_clean}_data_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # TXT - Summary report
        txt_file = f'{cve_clean}_report_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write(f"CVE VULNERABILITY REPORT\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"CVE: {results['cve_id']}\n")
            f.write(f"Generated: {results['timestamp']}\n")
            f.write(f"CVSS Score: {results['cvss_score']}\n\n")
            f.write(f"TOTAL VULNERABLE SYSTEMS: {results['total_vulnerable_systems']}\n")
            f.write(f"Systems with details retrieved: {results['systems_retrieved']}\n\n")
            
            if results['systems']:
                f.write(f"AFFECTED SYSTEMS:\n")
                for i, system in enumerate(sorted(results['systems'], key=lambda x: x['name']), 1):
                    f.write(f"{i}. {system['name']} - {system['ip_address']}\n")


def main():
    parser = argparse.ArgumentParser(
        description='ServiceNow CVE Analyzer - Find total count of vulnerable systems'
    )
    parser.add_argument('cve_ids', nargs='+', help='CVE ID(s) to analyze')
    parser.add_argument('-c', '--config', default='config.json', 
                       help='Config file (default: config.json)')
    parser.add_argument('--full', action='store_true',
                       help='Fetch full details for all systems (slower)')
    parser.add_argument('--include-patched', action='store_true',
                       help='Include patched/remediated systems in the count')
    
    args = parser.parse_args()
    
    # Load config
    if not os.path.exists(args.config):
        print(f"❌ Config file '{args.config}' not found")
        print("\nCreate a config.json file with:")
        print(json.dumps({
            "instance_url": "https://myinstance.service-now.com",
            "client_id": "your_oauth_client_id",
            "client_secret": "your_oauth_client_secret",
            "username": "your_username",
            "password": "your_password"
        }, indent=2))
        sys.exit(1)
    
    with open(args.config, 'r') as f:
        config = json.load(f)
    
    # Create analyzer
    analyzer = ServiceNowCVEAnalyzer(**config)
    
    # Process each CVE
    for cve_id in args.cve_ids:
        # Normalize CVE format
        if not cve_id.upper().startswith('CVE-'):
            cve_id = f"CVE-{cve_id}"
        cve_id = cve_id.upper()
        
        # Analyze
        results = analyzer.analyze_cve(cve_id, args.full, args.include_patched)
        
        # Display
        analyzer.display_results(results)
        
        # Export
        if results['found']:
            analyzer.export_results(results)
        
        print()


if __name__ == "__main__":
    main()