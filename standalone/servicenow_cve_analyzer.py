#!/usr/bin/env python3
"""
ServiceNow Vulnerability Analyzer
Main goal: Find how many systems are vulnerable to a specific CVE or QID
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


class ServiceNowVulnerabilityAnalyzer:
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
        # Extract instance name from URL for generating direct links
        self.instance_name = self.instance_url.replace('https://', '').replace('.service-now.com', '')
        
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
    
    def generate_servicenow_url(self, qid: str, state_filter: str = "!%3D3") -> str:
        """
        Generate a direct URL to ServiceNow vulnerability list for a specific QID.
        
        Args:
            qid: The QID value (e.g., "QID-92307" or "92307")
            state_filter: State filter for the URL (default: "!%3D3" meaning not closed)
        
        Returns:
            Full URL to ServiceNow vulnerability list filtered by QID
        """
        # Ensure QID format
        if not qid.startswith('QID-'):
            qid = f'QID-{qid}'
        
        # Build the URL with proper encoding
        base_url = f"https://{self.instance_name}.service-now.com/now/nav/ui/classic/params/target/"
        query_part = f"sn_vul_vulnerable_item_list.do%3Fsysparm_query%3DGOTOvulnerability.id%253E%253D{qid}%255Estate{state_filter}%26sysparm_first_row%3D1%26sysparm_view%3D"
        
        return base_url + query_part
    
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
    
    def analyze_vulnerability(self, vuln_id: str, fetch_all_details: bool = False, include_patched: bool = False, confirmation_state: str = None) -> Dict:
        """
        Main function: Analyze CVE or QID and count vulnerable systems.
        
        Args:
            vuln_id: CVE identifier (CVE-YYYY-NNNNN) or QID (numeric Qualys ID)
            fetch_all_details: If True, fetch details for all systems (slower)
                              If False, use counts from metadata and fetch sample (faster)
            confirmation_state: Filter by confirmation state:
                              - 'confirmed': Only confirmed vulnerabilities
                              - 'potential': All potential vulnerabilities
                              - 'potential-investigation': Potential - Investigation Required
                              - 'potential-patch': Potential - Deferred - Awaiting Patch  
                              - 'potential-low': Potential - Deferred - Low Risk
                              - None: All vulnerabilities (default)
        """
        print(f"\n{'=' * 80}")
        print(f"🔍 ANALYZING {vuln_id}")
        print(f"{'=' * 80}")
        
        # Determine vulnerability type and extract ID
        if vuln_id.upper().startswith('QID-'):
            vuln_type = 'QID'
            qid_number = vuln_id[4:]  # Remove 'QID-' prefix
        elif vuln_id.isdigit():
            vuln_type = 'QID'
            qid_number = vuln_id
            vuln_id = f'QID-{vuln_id}'  # Add QID- prefix for display
        else:
            vuln_type = 'CVE'
            qid_number = None
        
        results = {
            'vuln_id': vuln_id,
            'vuln_type': vuln_type,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'found': False,
            'total_vulnerable_systems': 0,
            'systems': []
        }
        
        # Check if this is a QID or CVE
        if vuln_type == 'QID':
            # This is a QID - search directly in third-party entries
            print(f"\nSearching for QID-{qid_number}...")
            params = {
                'sysparm_query': f'id=QID-{qid_number}',
                'sysparm_limit': '1'
            }
            
            third_party_result = self.api_request('/api/now/table/sn_vul_third_party_entry', params)
            if not third_party_result or not third_party_result.get('result'):
                print(f"❌ QID-{qid_number} not found in ServiceNow")
                return results
            
            third_party_entries = third_party_result['result']
            results['found'] = True
            
            # Get CVE information if available from the third-party entry
            tp_entry = third_party_entries[0]
            results['source'] = tp_entry.get('source', 'Qualys')
            results['summary'] = tp_entry.get('summary', tp_entry.get('description', 'N/A'))
            results['cvss_score'] = tp_entry.get('cvss_base_score', 'N/A')
            
            # Try to get associated CVEs if available
            cves_list = tp_entry.get('cves_list', '')
            if cves_list:
                results['associated_cves'] = cves_list
            
            # Generate ServiceNow URL for this QID
            results['servicenow_url'] = self.generate_servicenow_url(qid_number)
            
            print(f"✅ Found QID - Source: {results['source']} - CVSS Score: {results['cvss_score']}")
            
        else:
            # This is a CVE - use the original logic
            results['vuln_type'] = 'CVE'
            results['cve_id'] = vuln_id  # Keep for backwards compatibility
            
            # Step 1: Find CVE in NVD entries
            print(f"\nSearching for {vuln_id}...")
            params = {
                'sysparm_query': f'id={vuln_id}',
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
                # Set required fields for display_results
                results['systems'] = []
                results['systems_retrieved'] = 0
                results['sample_only'] = False
                return results
            
            third_party_entries = third_party_result['result']
        
        # Map confirmation states to u_confirmed_potential values
        confirmation_map = {
            'confirmed': '1',
            'potential': ['2', '3', '4'],  # All potential states
            'potential-investigation': '2',
            'potential-patch': '3',
            'potential-low': '4'
        }
        
        # Calculate TOTAL from scanner metadata
        total_active = sum(int(tp.get('count_active_vi', 0)) for tp in third_party_entries)
        total_all_time = sum(int(tp.get('total_vis', 0)) for tp in third_party_entries)
        
        # Note: These totals are from metadata and don't reflect confirmation state filtering
        # The actual filtered count will be determined when fetching vulnerable items
        results['total_vulnerable_systems'] = total_active
        results['total_all_time'] = total_all_time
        results['confirmation_filter'] = confirmation_state
        
        print(f"\n📊 VULNERABILITY COUNTS (from metadata):")
        print(f"   Currently Vulnerable (Active): {total_active}")
        print(f"   All-Time Total (Inc. Patched): {total_all_time}")
        if confirmation_state:
            print(f"   ⚠️  Note: Filtering by confirmation state: {confirmation_state}")
        
        # Show breakdown by source and collect ServiceNow URLs
        servicenow_urls = []
        for tp in third_party_entries:
            source = tp.get('source', 'Unknown')
            qid = tp.get('id', 'N/A')
            active = int(tp.get('count_active_vi', 0))
            total = int(tp.get('total_vis', 0))
            print(f"   • {source} {qid}: {active} active / {total} total")
            
            # Generate ServiceNow URL for each QID
            if qid != 'N/A':
                url = self.generate_servicenow_url(qid)
                servicenow_urls.append({'qid': qid, 'source': source, 'url': url})
        
        # Add URLs to results
        if servicenow_urls:
            results['servicenow_urls'] = servicenow_urls
        
        # Step 3: Get system details (full or sample based on count and preference)
        if total_active == 0:
            print("No vulnerable systems found")
            # Set required fields for display_results
            results['systems'] = []
            results['systems_retrieved'] = 0
            results['sample_only'] = False
            return results
        
        print(f"\nRetrieving system details...")
        
        # Decide how many details to fetch
        if fetch_all_details or total_active <= 100:
            # Fetch all if requested or if count is reasonable
            limit_per_query = min(1000, total_active)
            sample_only = False
        else:
            # Fetch sample for performance
            limit_per_query = 10
            sample_only = True
        
        systems = []
        seen_systems = set()
        
        for tp in third_party_entries:
            tp_sys_id = tp.get('sys_id')
            
            # Build query with filters
            query_parts = [f'vulnerability={tp_sys_id}']
            
            # Add active status filter
            if not include_patched:
                query_parts.append('active=true')
                query_parts.append('state=1')  # Only Open state vulnerabilities
            
            # Add confirmation state filter
            if confirmation_state and confirmation_state in confirmation_map:
                conf_value = confirmation_map[confirmation_state]
                if isinstance(conf_value, list):
                    # For 'potential' - include all potential states
                    conf_queries = [f'u_confirmed_potential={v}' for v in conf_value]
                    query_parts.append(f"({'^OR'.join(conf_queries)})")
                else:
                    query_parts.append(f'u_confirmed_potential={conf_value}')
            elif confirmation_state == 'none':
                # Explicitly filter for empty/none confirmation state
                query_parts.append('u_confirmed_potentialISEMPTY')
            
            query = '^'.join(query_parts)
            
            params = {
                'sysparm_query': query,
                'sysparm_limit': str(limit_per_query),
                'sysparm_fields': 'sys_id,number,cmdb_ci,short_description,active,state,u_confirmed_potential,assignment_group'
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
                                
                                # Get assignment group name if available
                                assignment_group_name = 'N/A'
                                ag_ref = vi.get('assignment_group', {})
                                if isinstance(ag_ref, dict) and ag_ref.get('value'):
                                    ag_id = ag_ref['value']
                                    ag_result = self.api_request(f'/api/now/table/sys_user_group/{ag_id}')
                                    if ag_result and ag_result.get('result'):
                                        assignment_group_name = ag_result['result'].get('name', 'Unknown')
                                
                                systems.append({
                                    'name': ci.get('name', 'Unknown'),
                                    'ip_address': ci.get('ip_address', 'N/A'),
                                    'type': ci.get('sys_class_name', 'Unknown'),
                                    'status': ci.get('operational_status', ''),
                                    'vi_number': vi.get('number', ''),
                                    'description': vi.get('short_description', ''),
                                    'assignment_group': assignment_group_name
                                })
                            
                            # Stop if we have enough for sample
                            if sample_only and len(systems) >= limit_per_query:
                                break
        
        results['systems'] = systems
        results['systems_retrieved'] = len(systems)
        results['sample_only'] = sample_only
        
        # Update total count if we filtered by confirmation state
        if confirmation_state:
            # The actual count after filtering
            results['filtered_vulnerable_systems'] = len(seen_systems)
            print(f"\n📊 FILTERED COUNTS:")
            print(f"   After confirmation state filter ({confirmation_state}): {len(seen_systems)}")
        
        return results
    
    def display_results(self, results: Dict):
        """Display results with focus on TOTAL COUNT."""
        if not results['found']:
            return
        
        vuln_id = results.get('vuln_id', results.get('cve_id', 'Unknown'))
        vuln_type = results.get('vuln_type', 'CVE')
        
        print(f"\n{'=' * 80}")
        print(f"📊 RESULTS for {vuln_type} {vuln_id}")
        print(f"{'=' * 80}")
        
        # The most important information - TOTAL COUNT
        if 'filtered_vulnerable_systems' in results:
            total = results['filtered_vulnerable_systems']
            print(f"\n🔴 TOTAL VULNERABLE SYSTEMS (Filtered - {results.get('confirmation_filter', 'all')}): {total}")
            print(f"   (Unfiltered total: {results['total_vulnerable_systems']})\n")
        else:
            total = results['total_vulnerable_systems']
            print(f"\n🔴 TOTAL VULNERABLE SYSTEMS: {total}\n")
        
        print(f"CVSS Score: {results['cvss_score']}")
        if 'published' in results:
            print(f"Published: {results['published']}")
        if 'source' in results:
            print(f"Source: {results['source']}")
        if 'associated_cves' in results:
            print(f"Associated CVEs: {results['associated_cves']}")
        
        # Display ServiceNow URLs
        if 'servicenow_url' in results:
            print(f"\n🔗 ServiceNow Direct Link:")
            print(f"   {results['servicenow_url']}")
        elif 'servicenow_urls' in results:
            print(f"\n🔗 ServiceNow Direct Links:")
            for url_info in results['servicenow_urls']:
                print(f"   • {url_info['source']} {url_info['qid']}: {url_info['url']}")
        
        # Show systems list
        systems = results.get('systems', [])
        retrieved = results.get('systems_retrieved', 0)
        sample_only = results.get('sample_only', False)
        
        if systems:
            if sample_only:
                print(f"\n📋 SAMPLE SYSTEMS (showing {min(10, len(systems))} of {total}):")
            else:
                print(f"\n📋 VULNERABLE SYSTEMS (showing {min(10, len(systems))} of {retrieved}):")
            
            print("-" * 60)
            
            # Show first 10 systems
            for i, system in enumerate(sorted(systems, key=lambda x: x['name'])[:10], 1):
                print(f"\n{i}. {system['name']}")
                print(f"   VIT: {system.get('vi_number', 'N/A')}")
                print(f"   IP: {system['ip_address']}")
                if system.get('assignment_group') and system['assignment_group'] != 'N/A':
                    print(f"   Assigned to: {system['assignment_group']}")
                if system.get('description'):
                    print(f"   Issue: {system['description'][:60]}")
            
            if len(systems) > 10:
                print(f"\n... and {len(systems) - 10} more systems")
        
        # Summary message
        if sample_only and retrieved > 0:
            print(f"\n💡 Retrieved details for {retrieved} systems (sample)")
            print(f"   Full enumeration would require fetching {total} records")
        
        # Export tip
        print(f"\n💾 Use --export flag to save results to CSV, JSON, and TXT files")
    
    def search_by_confirmation_status(self, confirmation_state: str, days: int = 14, fetch_all_details: bool = False) -> Dict:
        """
        Search for all vulnerabilities with a specific confirmation status found in the last N days.
        
        Args:
            confirmation_state: Confirmation state to search for:
                              - 'confirmed': Confirmed vulnerabilities
                              - 'potential': All potential vulnerabilities
                              - 'potential-investigation': Potential - Investigation Required
                              - 'potential-patch': Potential - Deferred - Awaiting Patch  
                              - 'potential-low': Potential - Deferred - Low Risk
                              - 'none': No confirmation state set
            days: Number of days to look back (default: 14)
            fetch_all_details: If True, fetch details for all systems (slower)
        """
        print(f"\n{'=' * 80}")
        print(f"🔍 SEARCHING FOR {confirmation_state.upper()} VULNERABILITIES")
        print(f"📅 From last {days} days")
        print(f"{'=' * 80}")
        
        # Map confirmation states to u_confirmed_potential values
        confirmation_map = {
            'confirmed': '1',
            'potential': ['2', '3', '4'],  # All potential states
            'potential-investigation': '2',
            'potential-patch': '3',
            'potential-low': '4'
        }
        
        results = {
            'search_type': 'confirmation_status',
            'confirmation_state': confirmation_state,
            'days': days,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'total_vulnerable_items': 0,
            'unique_vulnerabilities': 0,
            'systems': []
        }
        
        # Calculate date range
        from datetime import datetime, timedelta
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_date_str = start_date.strftime('%Y-%m-%d')
        
        print(f"\nSearching for vulnerable items since {start_date_str}...")
        
        # Build query for vulnerable items
        query_parts = []
        query_parts.append(f'first_found>={start_date_str}')
        query_parts.append('active=true')  # Only active vulnerabilities
        query_parts.append('state=1')  # Only Open state vulnerabilities
        
        # Add confirmation state filter
        if confirmation_state and confirmation_state in confirmation_map:
            conf_value = confirmation_map[confirmation_state]
            if isinstance(conf_value, list):
                # For 'potential' - include all potential states
                conf_queries = [f'u_confirmed_potential={v}' for v in conf_value]
                query_parts.append(f"({'^OR'.join(conf_queries)})")
            else:
                query_parts.append(f'u_confirmed_potential={conf_value}')
        elif confirmation_state == 'none':
            # Explicitly filter for empty/none confirmation state
            query_parts.append('u_confirmed_potentialISEMPTY')
        
        query = '^'.join(query_parts)
        
        # Fetch vulnerable items
        limit = 1000 if fetch_all_details else 500
        params = {
            'sysparm_query': query,
            'sysparm_limit': str(limit),
            'sysparm_fields': 'sys_id,number,vulnerability,cmdb_ci,short_description,first_found,ip_address,dns,risk_score,u_confirmed_potential,state,assignment_group'
        }
        
        vi_result = self.api_request('/api/now/table/sn_vul_vulnerable_item', params)
        
        if not vi_result or not vi_result.get('result'):
            print("No vulnerabilities found matching criteria")
            return results
        
        vulnerable_items = vi_result['result']
        results['total_vulnerable_items'] = len(vulnerable_items)
        
        print(f"Found {len(vulnerable_items)} vulnerable items")
        
        # Group by vulnerability
        from collections import defaultdict
        vuln_groups = defaultdict(list)
        seen_systems = set()
        
        for vi in vulnerable_items:
            vuln_ref = vi.get('vulnerability', {})
            if isinstance(vuln_ref, dict) and vuln_ref.get('value'):
                vuln_id = vuln_ref['value']
                vuln_groups[vuln_id].append(vi)
                
                # Track unique systems
                ci_ref = vi.get('cmdb_ci', {})
                if isinstance(ci_ref, dict) and ci_ref.get('value'):
                    ci_id = ci_ref['value']
                    if ci_id not in seen_systems:
                        seen_systems.add(ci_id)
                        
                        # Get assignment group name if available
                        assignment_group_name = 'N/A'
                        ag_ref = vi.get('assignment_group', {})
                        if isinstance(ag_ref, dict) and ag_ref.get('value'):
                            ag_id = ag_ref['value']
                            ag_result = self.api_request(f'/api/now/table/sys_user_group/{ag_id}')
                            if ag_result and ag_result.get('result'):
                                assignment_group_name = ag_result['result'].get('name', 'Unknown')
                        
                        results['systems'].append({
                            'ci_id': ci_id,
                            'vi_number': vi.get('number', 'N/A'),
                            'ip_address': vi.get('ip_address', 'N/A'),
                            'dns': vi.get('dns', 'N/A'),
                            'risk_score': vi.get('risk_score', 0),
                            'first_found': vi.get('first_found', ''),
                            'description': vi.get('short_description', ''),
                            'assignment_group': assignment_group_name
                        })
        
        results['unique_vulnerabilities'] = len(vuln_groups)
        results['unique_systems'] = len(seen_systems)
        
        print(f"\n📊 SUMMARY:")
        print(f"   Unique vulnerabilities: {len(vuln_groups)}")
        print(f"   Unique systems affected: {len(seen_systems)}")
        print(f"   Total vulnerable items: {len(vulnerable_items)}")
        
        # Get details for each unique vulnerability
        print(f"\nFetching vulnerability details...")
        for vuln_sys_id, items in list(vuln_groups.items())[:100]:  # Limit to first 100 vulns
            # Get vulnerability entry details
            vuln_result = self.api_request(f'/api/now/table/sn_vul_entry/{vuln_sys_id}')
            
            if vuln_result and vuln_result.get('result'):
                vuln_entry = vuln_result['result']
                
                # Check if it's a third-party entry to get QID/CVE info
                tp_result = self.api_request('/api/now/table/sn_vul_third_party_entry', {
                    'sysparm_query': f'sys_id={vuln_sys_id}',
                    'sysparm_limit': '1'
                })
                
                vuln_info = {
                    'sys_id': vuln_sys_id,
                    'id': vuln_entry.get('id', 'Unknown'),
                    'summary': vuln_entry.get('summary', vuln_entry.get('description', 'N/A')),
                    'cvss_score': vuln_entry.get('cvss_base_score', vuln_entry.get('v3_base_score', 'N/A')),
                    'affected_systems': len(items),
                    'items': items[:10],  # Sample of affected items
                    'cve_ids': []  # Will store associated CVEs
                }
                
                # If it's a third-party entry, get the QID and associated CVEs
                if tp_result and tp_result.get('result'):
                    tp_entry = tp_result['result'][0]
                    vuln_info['id'] = tp_entry.get('id', vuln_info['id'])
                    vuln_info['source'] = tp_entry.get('source', 'Unknown')
                    
                    # Get associated CVEs from cves_list field
                    cves_list = tp_entry.get('cves_list', '')
                    if cves_list:
                        # Handle both comma-separated and single sys_ids
                        if ',' in cves_list:
                            cve_sys_ids = [cve_id.strip() for cve_id in cves_list.split(',') if cve_id.strip()]
                        else:
                            cve_sys_ids = [cves_list.strip()] if cves_list.strip() else []
                        
                        cve_ids = []
                        
                        # Fetch each CVE entry to get the actual CVE ID (limit for performance)
                        for cve_sys_id in cve_sys_ids[:5]:  # Limit to first 5 CVEs
                            if cve_sys_id and len(cve_sys_id) == 32:  # Valid sys_id length
                                cve_result = self.api_request(f'/api/now/table/sn_vul_nvd_entry/{cve_sys_id}')
                                if cve_result and cve_result.get('result'):
                                    cve_entry = cve_result['result']
                                    cve_id = cve_entry.get('id', '')
                                    if cve_id and cve_id.startswith('CVE-'):
                                        cve_ids.append(cve_id)
                        
                        vuln_info['cve_ids'] = cve_ids
                
                results['vulnerabilities'].append(vuln_info)
        
        return results
    
    def display_status_search_results(self, results: Dict):
        """Display results from confirmation status search."""
        if results.get('search_type') != 'confirmation_status':
            return
        
        print(f"\n{'=' * 80}")
        print(f"📊 RESULTS: {results['confirmation_state'].upper()} VULNERABILITIES")
        print(f"{'=' * 80}")
        
        print(f"\n🔴 SUMMARY:")
        print(f"   Unique vulnerabilities: {results['unique_vulnerabilities']}")
        print(f"   Unique systems affected: {results['unique_systems']}")
        print(f"   Total vulnerable items: {results['total_vulnerable_items']}")
        print(f"   Time period: Last {results['days']} days\n")
        
        # Show top vulnerabilities
        if results['vulnerabilities']:
            print(f"TOP VULNERABILITIES (by affected systems):")
            print("-" * 60)
            
            # Sort by number of affected systems
            sorted_vulns = sorted(results['vulnerabilities'], 
                                key=lambda x: x['affected_systems'], 
                                reverse=True)
            
            for i, vuln in enumerate(sorted_vulns[:10], 1):
                print(f"\n{i}. {vuln['id']}")
                # Show associated CVEs if available
                if vuln.get('cve_ids'):
                    cve_display = ', '.join(vuln['cve_ids'][:3])  # Show first 3 CVEs
                    if len(vuln['cve_ids']) > 3:
                        cve_display += f' (+{len(vuln["cve_ids"]) - 3} more)'
                    print(f"   CVEs: {cve_display}")
                print(f"   Summary: {vuln['summary'][:80]}..." if len(vuln['summary']) > 80 else f"   Summary: {vuln['summary']}")
                print(f"   CVSS Score: {vuln['cvss_score']}")
                print(f"   Affected Systems: {vuln['affected_systems']}")
                if 'source' in vuln:
                    print(f"   Source: {vuln['source']}")
        
        # Show top affected systems
        if results['systems']:
            print(f"\n\nTOP AFFECTED SYSTEMS (by risk score):")
            print("-" * 60)
            
            # Sort by risk score
            sorted_systems = sorted(results['systems'], 
                                  key=lambda x: x.get('risk_score', 0), 
                                  reverse=True)
            
            for i, system in enumerate(sorted_systems[:10], 1):
                print(f"\n{i}. {system['dns']}")
                print(f"   VIT: {system.get('vi_number', 'N/A')}")
                print(f"   IP: {system['ip_address']}")
                print(f"   Risk Score: {system['risk_score']}")
                if system.get('assignment_group') and system['assignment_group'] != 'N/A':
                    print(f"   Assigned to: {system['assignment_group']}")
                print(f"   First Found: {system['first_found']}")
        
        # Export tip
        print(f"\n💾 Use --export flag to save results to CSV, JSON, and TXT files")
    
    def export_status_search_results(self, results: Dict):
        """Export results from confirmation status search."""
        if results.get('search_type') != 'confirmation_status':
            return
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        state = results['confirmation_state']
        
        # CSV - Vulnerability summary
        csv_file = f'status_search_{state}_{timestamp}_vulnerabilities.csv'
        with open(csv_file, 'w') as f:
            f.write('Vulnerability ID,CVE IDs,Summary,CVSS Score,Affected Systems,Source\n')
            for vuln in results['vulnerabilities']:
                cve_ids = ', '.join(vuln.get('cve_ids', [])) if vuln.get('cve_ids') else 'N/A'
                f.write(f'"{vuln["id"]}","{cve_ids}","{vuln["summary"]}",')
                f.write(f'"{vuln["cvss_score"]}","{vuln["affected_systems"]}",')
                f.write(f'"{vuln.get("source", "Unknown")}"\n')
        
        # CSV - System list
        csv_file2 = f'status_search_{state}_{timestamp}_systems.csv'
        with open(csv_file2, 'w') as f:
            f.write('DNS Name,VIT Number,IP Address,Risk Score,Assignment Group,First Found,Description\n')
            for system in results['systems']:
                f.write(f'"{system["dns"]}","{system.get("vi_number", "N/A")}",')
                f.write(f'"{system["ip_address"]}","{system["risk_score"]}",')
                f.write(f'"{system.get("assignment_group", "N/A")}","{system["first_found"]}",')
                f.write(f'"{system["description"]}"\n')
        
        # JSON - Full data
        json_file = f'status_search_{state}_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # TXT - Summary report
        txt_file = f'status_search_{state}_{timestamp}_report.txt'
        with open(txt_file, 'w') as f:
            f.write(f"VULNERABILITY STATUS SEARCH REPORT\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Search Type: {results['confirmation_state']}\n")
            f.write(f"Time Period: Last {results['days']} days\n")
            f.write(f"Generated: {results['timestamp']}\n\n")
            f.write(f"SUMMARY:\n")
            f.write(f"Unique Vulnerabilities: {results['unique_vulnerabilities']}\n")
            f.write(f"Unique Systems Affected: {results['unique_systems']}\n")
            f.write(f"Total Vulnerable Items: {results['total_vulnerable_items']}\n\n")
            
            if results['vulnerabilities']:
                f.write(f"TOP VULNERABILITIES:\n")
                sorted_vulns = sorted(results['vulnerabilities'], 
                                    key=lambda x: x['affected_systems'], 
                                    reverse=True)
                for i, vuln in enumerate(sorted_vulns[:20], 1):
                    cve_info = ''
                    if vuln.get('cve_ids'):
                        cve_info = f" ({', '.join(vuln['cve_ids'][:2])})"
                    f.write(f"{i}. {vuln['id']}{cve_info} - {vuln['affected_systems']} systems\n")
        
        # Return exported filenames for optional display
        return [csv_file, csv_file2, json_file, txt_file]
    
    def generate_llm_output(self, results: Dict):
        """Generate structured output optimized for LLM analysis."""
        if results.get('search_type') != 'confirmation_status':
            return
        
        print("=" * 80)
        print("VULNERABILITY ASSESSMENT DATA FOR LLM ANALYSIS")
        print("=" * 80)
        
        # Metadata section
        print("\n[METADATA]")
        print(f"scan_date: {results['timestamp']}")
        print(f"confirmation_type: {results['confirmation_state']}")
        print(f"time_period_days: {results['days']}")
        print(f"total_unique_vulnerabilities: {results['unique_vulnerabilities']}")
        print(f"total_unique_systems: {results['unique_systems']}")
        print(f"total_vulnerable_items: {results['total_vulnerable_items']}")
        
        # Detailed vulnerabilities section with all data
        print("\n[VULNERABILITIES]")
        
        # Sort by criticality (CVSS * affected systems)
        sorted_vulns = sorted(results['vulnerabilities'], 
                            key=lambda x: (self._calculate_priority_score(x), 
                                         x['affected_systems']), 
                            reverse=True)
        
        for i, vuln in enumerate(sorted_vulns, 1):
            print(f"\nVULN_{i}:")
            print(f"  id: {vuln['id']}")
            
            # Include all CVEs, not truncated
            if vuln.get('cve_ids'):
                print(f"  cve_ids: {', '.join(vuln['cve_ids'])}")
            else:
                print(f"  cve_ids: NONE")
            
            # Clean summary for better parsing
            summary = vuln['summary'].replace('\n', ' ').strip()
            print(f"  summary: {summary}")
            
            # CVSS score with proper handling
            cvss = vuln.get('cvss_score', 'N/A')
            if cvss == '' or cvss is None:
                cvss = 'N/A'
            print(f"  cvss_score: {cvss}")
            
            # Calculate severity level
            severity = self._calculate_severity(cvss)
            print(f"  severity_level: {severity}")
            
            print(f"  affected_systems_count: {vuln['affected_systems']}")
            print(f"  source: {vuln.get('source', 'Unknown')}")
            
            # Priority score for sorting
            priority = self._calculate_priority_score(vuln)
            print(f"  calculated_priority_score: {priority}")
            
            # Risk indicators
            risk_indicators = self._identify_risk_indicators(vuln)
            if risk_indicators:
                print(f"  risk_indicators: {', '.join(risk_indicators)}")
        
        # Systems section with risk analysis
        print("\n[AFFECTED_SYSTEMS]")
        
        # Sort by risk score
        sorted_systems = sorted(results['systems'], 
                              key=lambda x: x.get('risk_score', 0), 
                              reverse=True)
        
        # Group systems by risk level
        critical_systems = [s for s in sorted_systems if s.get('risk_score', 0) >= 90]
        high_risk_systems = [s for s in sorted_systems if 70 <= s.get('risk_score', 0) < 90]
        medium_risk_systems = [s for s in sorted_systems if 40 <= s.get('risk_score', 0) < 70]
        low_risk_systems = [s for s in sorted_systems if s.get('risk_score', 0) < 40]
        
        print(f"\ncritical_risk_systems_count: {len(critical_systems)}")
        print(f"high_risk_systems_count: {len(high_risk_systems)}")
        print(f"medium_risk_systems_count: {len(medium_risk_systems)}")
        print(f"low_risk_systems_count: {len(low_risk_systems)}")
        
        # Detail critical and high-risk systems
        if critical_systems:
            print("\nCRITICAL_SYSTEMS:")
            for system in critical_systems[:10]:
                print(f"  - hostname: {system['dns']}")
                print(f"    ip: {system['ip_address']}")
                print(f"    risk_score: {system['risk_score']}")
                print(f"    first_found: {system['first_found']}")
                print(f"    system_type: {self._identify_system_type(system['dns'])}")
        
        if high_risk_systems:
            print("\nHIGH_RISK_SYSTEMS:")
            for system in high_risk_systems[:10]:
                print(f"  - hostname: {system['dns']}")
                print(f"    risk_score: {system['risk_score']}")
                print(f"    system_type: {self._identify_system_type(system['dns'])}")
        
        # Analysis helpers section
        print("\n[ANALYSIS_METRICS]")
        
        # CVSS distribution
        cvss_dist = self._calculate_cvss_distribution(sorted_vulns)
        print(f"\ncvss_distribution:")
        print(f"  critical_9_10: {cvss_dist['critical']}")
        print(f"  high_7_9: {cvss_dist['high']}")
        print(f"  medium_4_7: {cvss_dist['medium']}")
        print(f"  low_0_4: {cvss_dist['low']}")
        print(f"  no_score: {cvss_dist['none']}")
        
        # Exposure analysis
        print(f"\nexposure_analysis:")
        widespread = [v for v in sorted_vulns if v['affected_systems'] >= 20]
        moderate = [v for v in sorted_vulns if 5 <= v['affected_systems'] < 20]
        limited = [v for v in sorted_vulns if v['affected_systems'] < 5]
        
        print(f"  widespread_20plus_systems: {len(widespread)}")
        print(f"  moderate_5_19_systems: {len(moderate)}")
        print(f"  limited_under_5_systems: {len(limited)}")
        
        # Vulnerability categories
        categories = self._categorize_vulnerabilities(sorted_vulns)
        print(f"\nvulnerability_categories:")
        for category, count in categories.items():
            print(f"  {category}: {count}")
        
        # Top vulnerability patterns
        print(f"\n[KEY_PATTERNS]")
        patterns = self._identify_patterns(sorted_vulns)
        for pattern_name, pattern_data in patterns.items():
            print(f"\n{pattern_name}:")
            for item in pattern_data:
                print(f"  - {item}")
        
        print("\n" + "=" * 80)
        print("END OF LLM ANALYSIS DATA")
        print("=" * 80)
    
    def _calculate_priority_score(self, vuln: Dict) -> float:
        """Calculate priority score based on CVSS and exposure."""
        cvss_str = vuln.get('cvss_score', '0')
        try:
            cvss = float(cvss_str) if cvss_str and cvss_str != 'N/A' else 0
        except (ValueError, TypeError):
            cvss = 0
        
        affected = vuln.get('affected_systems', 0)
        
        # Weight: CVSS (0-10) * 10 + affected systems * 2
        # This gives a max score of ~200 for critical widespread vulns
        return (cvss * 10) + (affected * 2)
    
    def _calculate_severity(self, cvss_str: str) -> str:
        """Convert CVSS score to severity level."""
        try:
            if not cvss_str or cvss_str == 'N/A' or cvss_str == '':
                return 'UNKNOWN'
            cvss = float(cvss_str)
            if cvss >= 9.0:
                return 'CRITICAL'
            elif cvss >= 7.0:
                return 'HIGH'
            elif cvss >= 4.0:
                return 'MEDIUM'
            elif cvss > 0:
                return 'LOW'
            else:
                return 'UNKNOWN'
        except (ValueError, TypeError):
            return 'UNKNOWN'
    
    def _identify_risk_indicators(self, vuln: Dict) -> List[str]:
        """Identify specific risk indicators in vulnerability."""
        indicators = []
        summary = vuln.get('summary', '').lower()
        
        if 'remote code execution' in summary or 'rce' in summary:
            indicators.append('REMOTE_CODE_EXECUTION')
        if 'privilege escalation' in summary or 'elevation of privilege' in summary:
            indicators.append('PRIVILEGE_ESCALATION')
        if 'authentication bypass' in summary:
            indicators.append('AUTH_BYPASS')
        if 'sql injection' in summary:
            indicators.append('SQL_INJECTION')
        if 'cross-site scripting' in summary or 'xss' in summary:
            indicators.append('XSS')
        if 'denial of service' in summary or 'dos' in summary:
            indicators.append('DENIAL_OF_SERVICE')
        if 'information disclosure' in summary:
            indicators.append('INFO_DISCLOSURE')
        if 'buffer overflow' in summary:
            indicators.append('BUFFER_OVERFLOW')
        if 'use after free' in summary:
            indicators.append('USE_AFTER_FREE')
        
        # Check for specific product indicators
        if 'windows' in summary:
            indicators.append('WINDOWS')
        if 'chrome' in summary or 'chromium' in summary:
            indicators.append('BROWSER')
        if 'microsoft office' in summary:
            indicators.append('OFFICE')
        if '.net' in summary:
            indicators.append('DOTNET')
        
        return indicators
    
    def _identify_system_type(self, hostname: str) -> str:
        """Identify system type from hostname."""
        hostname_lower = hostname.lower()
        
        if 'prd' in hostname_lower or 'prod' in hostname_lower:
            return 'PRODUCTION'
        elif 'dev' in hostname_lower or 'test' in hostname_lower:
            return 'DEVELOPMENT'
        elif 'stg' in hostname_lower or 'stage' in hostname_lower:
            return 'STAGING'
        elif 'dc' in hostname_lower:
            return 'DOMAIN_CONTROLLER'
        elif 'sql' in hostname_lower or 'db' in hostname_lower:
            return 'DATABASE'
        elif 'web' in hostname_lower or 'www' in hostname_lower:
            return 'WEB_SERVER'
        elif 'app' in hostname_lower:
            return 'APPLICATION_SERVER'
        else:
            return 'WORKSTATION'
    
    def _calculate_cvss_distribution(self, vulns: List[Dict]) -> Dict:
        """Calculate distribution of CVSS scores."""
        dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
        
        for vuln in vulns:
            severity = self._calculate_severity(vuln.get('cvss_score', 'N/A'))
            if severity == 'CRITICAL':
                dist['critical'] += 1
            elif severity == 'HIGH':
                dist['high'] += 1
            elif severity == 'MEDIUM':
                dist['medium'] += 1
            elif severity == 'LOW':
                dist['low'] += 1
            else:
                dist['none'] += 1
        
        return dist
    
    def _categorize_vulnerabilities(self, vulns: List[Dict]) -> Dict:
        """Categorize vulnerabilities by type."""
        categories = defaultdict(int)
        
        for vuln in vulns:
            indicators = self._identify_risk_indicators(vuln)
            for indicator in indicators:
                if indicator in ['REMOTE_CODE_EXECUTION', 'PRIVILEGE_ESCALATION', 
                               'AUTH_BYPASS', 'SQL_INJECTION', 'XSS', 
                               'DENIAL_OF_SERVICE', 'INFO_DISCLOSURE', 
                               'BUFFER_OVERFLOW', 'USE_AFTER_FREE']:
                    categories[indicator] += 1
        
        return dict(categories)
    
    def _identify_patterns(self, vulns: List[Dict]) -> Dict:
        """Identify patterns in vulnerabilities."""
        patterns = {
            'multiple_cves_single_qid': [],
            'widespread_critical': [],
            'zero_day_potential': []
        }
        
        from datetime import datetime
        current_year = datetime.now().year
        
        for vuln in vulns:
            # Multiple CVEs
            if vuln.get('cve_ids') and len(vuln['cve_ids']) > 3:
                patterns['multiple_cves_single_qid'].append(
                    f"{vuln['id']} has {len(vuln['cve_ids'])} CVEs"
                )
            
            # Widespread critical
            severity = self._calculate_severity(vuln.get('cvss_score', 'N/A'))
            if severity in ['CRITICAL', 'HIGH'] and vuln['affected_systems'] >= 20:
                patterns['widespread_critical'].append(
                    f"{vuln['id']} ({severity}) on {vuln['affected_systems']} systems"
                )
            
            # Potential zero-days (current year CVEs)
            if vuln.get('cve_ids'):
                for cve in vuln['cve_ids']:
                    if f'CVE-{current_year}' in cve:
                        patterns['zero_day_potential'].append(
                            f"{vuln['id']} has recent CVE: {cve}"
                        )
                        break
        
        # Limit pattern lists
        for key in patterns:
            patterns[key] = patterns[key][:5]
        
        return patterns
    
    def export_results(self, results: Dict):
        """Export results to files."""
        if not results['found']:
            return
            
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        vuln_id = results.get('vuln_id', results.get('cve_id', 'Unknown'))
        vuln_type = results.get('vuln_type', 'CVE')
        vuln_clean = f"{vuln_type}_{vuln_id}".replace('/', '_')
        
        # CSV - System list
        csv_file = f'{vuln_clean}_systems_{timestamp}.csv'
        with open(csv_file, 'w') as f:
            f.write('System Name,VIT Number,IP Address,Type,Status,Assignment Group,Issue\n')
            for system in sorted(results.get('systems', []), key=lambda x: x['name']):
                f.write(f'"{system["name"]}","{system.get("vi_number", "N/A")}",')
                f.write(f'"{system["ip_address"]}","{system["type"]}",')
                f.write(f'"{system["status"]}","{system.get("assignment_group", "N/A")}",')
                f.write(f'"{system["description"]}"\n')
        
        # JSON - Full data
        json_file = f'{vuln_clean}_data_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # TXT - Summary report
        txt_file = f'{vuln_clean}_report_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write(f"VULNERABILITY REPORT\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"{vuln_type}: {vuln_id}\n")
            f.write(f"Generated: {results['timestamp']}\n")
            f.write(f"CVSS Score: {results['cvss_score']}\n")
            
            # Add ServiceNow URLs to report
            if 'servicenow_url' in results:
                f.write(f"ServiceNow URL: {results['servicenow_url']}\n")
            elif 'servicenow_urls' in results:
                f.write(f"ServiceNow URLs:\n")
                for url_info in results['servicenow_urls']:
                    f.write(f"  • {url_info['source']} {url_info['qid']}: {url_info['url']}\n")
            f.write("\n")
            if 'filtered_vulnerable_systems' in results:
                f.write(f"TOTAL VULNERABLE SYSTEMS (Filtered - {results.get('confirmation_filter', 'all')}): {results['filtered_vulnerable_systems']}\n")
                f.write(f"TOTAL VULNERABLE SYSTEMS (Unfiltered): {results['total_vulnerable_systems']}\n")
            else:
                f.write(f"TOTAL VULNERABLE SYSTEMS: {results['total_vulnerable_systems']}\n")
            f.write(f"Systems with details retrieved: {results.get('systems_retrieved', 0)}\n\n")
            
            if results.get('systems'):
                f.write(f"AFFECTED SYSTEMS:\n")
                for i, system in enumerate(sorted(results['systems'], key=lambda x: x['name']), 1):
                    f.write(f"{i}. {system['name']} - {system['ip_address']}\n")


def main():
    parser = argparse.ArgumentParser(
        description='ServiceNow Vulnerability Analyzer - Find total count of vulnerable systems'
    )
    parser.add_argument('vuln_ids', nargs='*', help='CVE ID(s) or QID(s) to analyze (e.g., CVE-2024-1234 or QID-123456)')
    parser.add_argument('-c', '--config', default='config.json', 
                       help='Config file (default: config.json)')
    parser.add_argument('--full', action='store_true',
                       help='Fetch full details for all systems (slower)')
    parser.add_argument('--include-patched', action='store_true',
                       help='Include patched/remediated systems in the count')
    parser.add_argument('--confirmation', choices=['confirmed', 'potential', 'potential-investigation', 
                                                   'potential-patch', 'potential-low', 'none'],
                       help='Filter by confirmation state (confirmed, potential, etc.)')
    parser.add_argument('--status-search', choices=['confirmed', 'potential', 'potential-investigation',
                                                    'potential-patch', 'potential-low', 'none'],
                       help='Search for all vulnerabilities with this confirmation status')
    parser.add_argument('--days', type=int, default=14,
                       help='Number of days to look back for status search (default: 14)')
    parser.add_argument('--llm-output', action='store_true',
                       help='Generate LLM-friendly structured output for analysis')
    parser.add_argument('--export', action='store_true',
                       help='Export results to CSV, JSON, and TXT files')
    
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
    analyzer = ServiceNowVulnerabilityAnalyzer(**config)
    
    # Check if doing a status-based search
    if args.status_search:
        # Search by confirmation status
        results = analyzer.search_by_confirmation_status(args.status_search, args.days, args.full)
        
        if args.llm_output:
            # Generate LLM-friendly output
            analyzer.generate_llm_output(results)
        else:
            # Standard human-readable output
            analyzer.display_status_search_results(results)
        
        # Export if requested
        if args.export:
            analyzer.export_status_search_results(results)
            print(f"\n📁 Files exported for status search")
        
        sys.exit(0)
    
    # Validate that vuln_ids were provided for regular search
    if not args.vuln_ids:
        print("❌ Error: Must provide vulnerability IDs or use --status-search")
        parser.print_help()
        sys.exit(1)
    
    # Process each vulnerability ID (CVE or QID)
    for vuln_id in args.vuln_ids:
        # Normalize format
        if vuln_id.upper().startswith('QID-'):
            # It's a QID - normalize to uppercase
            vuln_id = vuln_id.upper()
        elif vuln_id.isdigit():
            # It's a numeric QID - add QID- prefix
            vuln_id = f"QID-{vuln_id}"
        else:
            # It's a CVE - normalize format
            if not vuln_id.upper().startswith('CVE-'):
                vuln_id = f"CVE-{vuln_id}"
            vuln_id = vuln_id.upper()
        
        # Analyze
        results = analyzer.analyze_vulnerability(vuln_id, args.full, args.include_patched, args.confirmation)
        
        # Display
        analyzer.display_results(results)
        
        # Export if requested
        if args.export and results['found']:
            analyzer.export_results(results)
            print(f"\n📁 Files exported:")
            print(f"   • CSV with system list")
            print(f"   • JSON with full details")
            print(f"   • TXT summary report")
        
        print()


if __name__ == "__main__":
    main()