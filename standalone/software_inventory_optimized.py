#!/usr/bin/env python3
"""
ServiceNow Software Inventory Analyzer - OPTIMIZED VERSION
Query cmdb_ci_spkg table to find installed software by manufacturer or name
Optimized for performance with batch queries and caching
"""

import requests
import json
import sys
import os
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import time
from collections import defaultdict


class SoftwareInventoryAnalyzer:
    def __init__(self, instance_url: str, client_id: str, client_secret: str, 
                 username: str, password: str, debug: bool = False):
        """Initialize ServiceNow client with OAuth2 credentials."""
        self.instance_url = instance_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.token_expiry = 0
        self.sam_access_denied = False
        self.permission_warnings = set()
        self.company_cache = {}  # Cache for company names
        self.host_cache = {}  # Cache for host details
        self.debug = debug  # Debug mode flag
        
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
            if response.status_code == 403:
                # Track permission issues for specific tables
                if 'cmdb_sam_sw_install' in endpoint:
                    self.sam_access_denied = True
                    if 'cmdb_sam_sw_install' not in self.permission_warnings:
                        self.permission_warnings.add('cmdb_sam_sw_install')
                        print(f"\n⚠️  Permission denied for cmdb_sam_sw_install table")
                        print(f"   This table requires the 'sam_user' or 'asset' role.")
                        print(f"   Falling back to relationship data (may be less detailed).\n")
                else:
                    print(f"⚠️  Access denied to {endpoint} - insufficient permissions")
                return None
            response.raise_for_status()
            return response.json()
        except Exception as e:
            if '403' in str(e):
                if 'cmdb_sam_sw_install' in endpoint:
                    self.sam_access_denied = True
                    if 'cmdb_sam_sw_install' not in self.permission_warnings:
                        self.permission_warnings.add('cmdb_sam_sw_install')
                        print(f"\n⚠️  Permission denied for cmdb_sam_sw_install table")
                        print(f"   This table requires the 'sam_user' or 'asset' role.")
                        print(f"   Falling back to relationship data (may be less detailed).\n")
                else:
                    print(f"API request failed: {e}")
            else:
                print(f"API request failed: {e}")
            return None
    
    def _batch_get_hosts(self, host_sys_ids: List[str]) -> Dict[str, Dict]:
        """
        Get details for multiple hosts in a single API call.
        
        Args:
            host_sys_ids: List of host sys_ids to fetch
        
        Returns:
            Dictionary mapping sys_id to host details
        """
        hosts = {}
        
        # Filter out already cached hosts
        uncached_ids = [sid for sid in host_sys_ids if sid not in self.host_cache]
        
        if not uncached_ids:
            # All hosts are cached, return from cache
            return {sid: self.host_cache[sid] for sid in host_sys_ids if sid in self.host_cache}
        
        # Batch query for uncached hosts
        # ServiceNow IN operator has a limit, so we batch in groups of 100
        for i in range(0, len(uncached_ids), 100):
            batch = uncached_ids[i:i+100]
            sys_id_list = ','.join(batch)
            
            params = {
                'sysparm_query': f'sys_idIN{sys_id_list}',
                'sysparm_limit': '100',
                'sysparm_fields': 'sys_id,name,ip_address,os,operating_system,sys_class_name'
            }
            
            response = self.api_request('/api/now/table/cmdb_ci', params)
            
            if response and response.get('result'):
                for host in response['result']:
                    host_details = {
                        'host_sys_id': host['sys_id'],
                        'host_name': host.get('name', 'Unknown'),
                        'host_ip': host.get('ip_address', 'N/A'),
                        'host_os': host.get('os', host.get('operating_system', 'Unknown')),
                        'host_class': host.get('sys_class_name', 'Unknown')
                    }
                    self.host_cache[host['sys_id']] = host_details
                    hosts[host['sys_id']] = host_details
        
        # Add cached hosts to the result
        for sid in host_sys_ids:
            if sid in self.host_cache and sid not in hosts:
                hosts[sid] = self.host_cache[sid]
        
        return hosts
    
    def _get_company_name(self, company_sys_id: str) -> str:
        """
        Get the company name for a given sys_id from the core_company table.
        
        Args:
            company_sys_id: sys_id of the company
        
        Returns:
            Company name or empty string if not found
        """
        # Check cache first
        if company_sys_id in self.company_cache:
            return self.company_cache[company_sys_id]
        
        params = {
            'sysparm_query': f'sys_id={company_sys_id}',
            'sysparm_limit': '1',
            'sysparm_fields': 'sys_id,name'
        }
        
        response = self.api_request('/api/now/table/core_company', params)
        
        if response and response.get('result'):
            name = response['result'][0].get('name', '')
            self.company_cache[company_sys_id] = name
            return name
        
        return ''
    
    def _get_company_sys_id(self, company_name: str) -> Optional[str]:
        """
        Get the sys_id for a company/manufacturer from the core_company table.
        
        Args:
            company_name: Name of the company/manufacturer
        
        Returns:
            sys_id of the company or None if not found
        """
        # Use LIKE query to find the company
        params = {
            'sysparm_query': f'nameLIKE{company_name}',
            'sysparm_limit': '10',
            'sysparm_fields': 'sys_id,name'
        }
        
        response = self.api_request('/api/now/table/core_company', params)
        
        if response and response.get('result'):
            # Look for exact match first
            for company in response['result']:
                if company.get('name', '').lower() == company_name.lower():
                    return company['sys_id']
            # If no exact match, return the first result
            return response['result'][0]['sys_id']
        
        return None
    
    def search_by_manufacturer(self, manufacturer: str, fetch_details: bool = True) -> Dict:
        """
        Search for all software packages from a specific manufacturer.
        
        Args:
            manufacturer: Manufacturer/vendor name (e.g., "Palo Alto Networks", "Microsoft")
                         Supports wildcards using * (e.g., "*axon", "Palo*", "*Alto*")
            fetch_details: If True, fetch installation details for each package
        
        Returns:
            Dictionary with software inventory information
        """
        # Handle wildcards - convert * to % for ServiceNow LIKE queries
        search_term = manufacturer.replace('*', '')
        is_wildcard = '*' in manufacturer
        
        print(f"\n{'=' * 80}")
        print(f"🔍 SEARCHING FOR SOFTWARE BY MANUFACTURER: {manufacturer}")
        if is_wildcard:
            print(f"   Using wildcard search pattern")
        print(f"{'=' * 80}\n")
        
        results = {
            'search_type': 'manufacturer',
            'manufacturer': manufacturer,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_packages': 0,
            'total_installations': 0,
            'unique_versions': {},
            'packages': [],
            'installations_by_host': defaultdict(list)
        }
        
        # Search for software packages by manufacturer/vendor
        print(f"Searching for software packages from {manufacturer}...")
        
        # First, try to get the company sys_id (only if not using wildcards)
        company_sys_id = None
        if not is_wildcard:
            company_sys_id = self._get_company_sys_id(search_term)
        else:
            # For wildcard searches, we'll use LIKE queries
            company_sys_id = None
        
        if not company_sys_id and not is_wildcard:
            print(f"Warning: Could not find company '{search_term}' in core_company table")
            print(f"Falling back to text-based search...")
        
        # Build queries - only search manufacturer field
        queries = []
        
        if is_wildcard:
            # For wildcard searches, first get all companies matching the pattern
            params = {
                'sysparm_query': f'nameLIKE{search_term}',
                'sysparm_limit': '100',
                'sysparm_fields': 'sys_id,name'
            }
            
            response = self.api_request('/api/now/table/core_company', params)
            
            if response and response.get('result'):
                print(f"Found {len(response['result'])} matching manufacturers")
                for company in response['result']:
                    queries.append((f'manufacturer={company["sys_id"]}', True))
            else:
                # Fallback to text-based LIKE query
                queries.append((f'manufacturerLIKE{search_term}', False))
        elif company_sys_id:
            # Use the sys_id for exact matching on manufacturer field only
            queries.append((f'manufacturer={company_sys_id}', True))
        else:
            # Fallback to LIKE query on manufacturer field if no company found
            queries.append((f'manufacturerLIKE{search_term}', False))
        
        all_packages = []
        seen_sys_ids = set()
        
        for query, is_exact in queries:
            params = {
                'sysparm_query': query,
                'sysparm_limit': '1000',
                'sysparm_fields': 'sys_id,name,version,manufacturer,vendor,publisher,install_count,install_status,short_description'
            }
            
            response = self.api_request('/api/now/table/cmdb_ci_spkg', params)
            
            if response and response.get('result'):
                for package in response['result']:
                    if package['sys_id'] not in seen_sys_ids:
                        # For exact queries, add directly
                        # For LIKE queries, verify the match
                        if is_exact:
                            seen_sys_ids.add(package['sys_id'])
                            all_packages.append(package)
                        else:
                            # For LIKE queries, verify by looking up the manufacturer company name
                            pkg_manufacturer_field = package.get('manufacturer', '')
                            
                            # Extract ID if it's a reference object
                            if isinstance(pkg_manufacturer_field, dict):
                                pkg_manufacturer_id = pkg_manufacturer_field.get('value', '')
                            else:
                                pkg_manufacturer_id = pkg_manufacturer_field
                            
                            # Get the company name for this manufacturer ID
                            if pkg_manufacturer_id:
                                manufacturer_name = self._get_company_name(pkg_manufacturer_id)
                                # For wildcard searches, check if the pattern matches
                                if is_wildcard:
                                    if manufacturer_name and search_term.lower() in manufacturer_name.lower():
                                        seen_sys_ids.add(package['sys_id'])
                                        all_packages.append(package)
                                else:
                                    if manufacturer_name and search_term.lower() in manufacturer_name.lower():
                                        seen_sys_ids.add(package['sys_id'])
                                        all_packages.append(package)
        
        if not all_packages:
            print(f"No software packages found from manufacturer: {manufacturer}")
            return results
        
        results['total_packages'] = len(all_packages)
        print(f"Found {len(all_packages)} software packages from {manufacturer}")
        
        # Process each package
        for package in all_packages:
            # Get manufacturer ID and resolve to name
            manufacturer_field = package.get('manufacturer') or package.get('vendor') or package.get('publisher') or ''
            
            # Extract ID if it's a reference object
            if isinstance(manufacturer_field, dict):
                manufacturer_id = manufacturer_field.get('value', '')
            else:
                manufacturer_id = manufacturer_field
            
            manufacturer_name = self._get_company_name(manufacturer_id) if manufacturer_id else 'Unknown'
            
            # Handle comma-formatted numbers in install_count
            install_count_str = str(package.get('install_count', 0))
            install_count = int(install_count_str.replace(',', '')) if install_count_str else 0
            
            pkg_info = {
                'sys_id': package['sys_id'],
                'name': package.get('name', 'Unknown'),
                'version': package.get('version', 'Unknown'),
                'manufacturer_id': manufacturer_id,
                'manufacturer': manufacturer_name,
                'install_count': install_count,
                'description': package.get('short_description', ''),
                'installations': []
            }
            
            # Track unique versions
            pkg_name = pkg_info['name']
            pkg_version = pkg_info['version']
            
            if pkg_name not in results['unique_versions']:
                results['unique_versions'][pkg_name] = {}
            
            if pkg_version not in results['unique_versions'][pkg_name]:
                results['unique_versions'][pkg_name][pkg_version] = {
                    'count': 0,
                    'hosts': []
                }
            
            # Get installation details if requested
            if fetch_details and pkg_info['install_count'] > 0:
                installations = self._get_software_installations_optimized(package['sys_id'])
                pkg_info['installations'] = installations
                
                # Update counts and host tracking
                if installations:
                    for install in installations:
                        host_name = install.get('host_name', 'Unknown')
                        results['installations_by_host'][host_name].append({
                            'software': pkg_name,
                            'version': pkg_version
                        })
                        
                        results['unique_versions'][pkg_name][pkg_version]['count'] += 1
                        if host_name not in results['unique_versions'][pkg_name][pkg_version]['hosts']:
                            results['unique_versions'][pkg_name][pkg_version]['hosts'].append(host_name)
                else:
                    # If we couldn't get installation details, still record the count from the package
                    results['unique_versions'][pkg_name][pkg_version]['count'] = pkg_info['install_count']
            else:
                # When not fetching details, use the install_count from the package
                results['unique_versions'][pkg_name][pkg_version]['count'] = pkg_info['install_count']
            
            results['packages'].append(pkg_info)
            results['total_installations'] += pkg_info['install_count']
        
        return results
    
    def search_by_software_name(self, software_name: str, fetch_details: bool = True) -> Dict:
        """
        Search for specific software by name.
        
        Args:
            software_name: Software name (e.g., "Cortex XDR", "Windows Server")
                          Supports wildcards using * (e.g., "*Office", "Windows*", "*Server*")
            fetch_details: If True, fetch installation details
        
        Returns:
            Dictionary with software inventory information
        """
        # Handle wildcards - convert * to % for ServiceNow LIKE queries
        search_term = software_name.replace('*', '')
        is_wildcard = '*' in software_name
        
        print(f"\n{'=' * 80}")
        print(f"🔍 SEARCHING FOR SOFTWARE: {software_name}")
        if is_wildcard:
            print(f"   Using wildcard search pattern")
        print(f"{'=' * 80}\n")
        
        results = {
            'search_type': 'software_name',
            'software_name': software_name,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_versions': 0,
            'total_installations': 0,
            'versions': {},
            'installations_by_host': defaultdict(list),
            'hosts_by_version': defaultdict(list)
        }
        
        print(f"Searching for '{software_name}' installations...")
        
        # Search for software by name (use search_term without wildcards)
        params = {
            'sysparm_query': f'nameLIKE{search_term}',
            'sysparm_limit': '1000',
            'sysparm_fields': 'sys_id,name,version,manufacturer,vendor,publisher,install_count,install_status,short_description'
        }
        
        response = self.api_request('/api/now/table/cmdb_ci_spkg', params)
        
        if not response or not response.get('result'):
            print(f"Software '{software_name}' not found in environment")
            return results
        
        packages = response['result']
        print(f"Found {len(packages)} version(s) of {software_name}")
        
        # Process each package individually
        for package in packages:
            version = package.get('version', 'Unknown')
            install_count_str = str(package.get('install_count', 0))
            install_count = int(install_count_str.replace(',', '')) if install_count_str else 0
            
            # Get manufacturer ID and name
            manufacturer_field = package.get('manufacturer') or package.get('vendor') or package.get('publisher') or ''
            
            # Extract ID if it's a reference object
            if isinstance(manufacturer_field, dict):
                manufacturer_id = manufacturer_field.get('value', '')
            else:
                manufacturer_id = manufacturer_field
                
            manufacturer_name = self._get_company_name(manufacturer_id) if manufacturer_id else 'Unknown'
            
            # Store package info
            if version not in results['versions']:
                results['versions'][version] = {
                    'sys_id': package['sys_id'],
                    'full_name': package.get('name', software_name),
                    'manufacturer': manufacturer_name,
                    'manufacturer_id': manufacturer_id,
                    'install_count': 0,
                    'hosts': []
                }
            
            # Add this package's install count to the version total
            results['versions'][version]['install_count'] += install_count
            results['total_installations'] += install_count
            
            # Get installation details if requested - use the correct package sys_id
            if fetch_details and install_count > 0:
                # Debug: Show which package we're processing
                if self.debug:
                    print(f"\n  Processing: {package.get('name')} v{version} (sys_id: {package['sys_id'][:8]}..., installs: {install_count})")
                
                installations = self._get_software_installations_optimized(package['sys_id'])
                
                if self.debug:
                    print(f"    Found {len(installations)} installations")
                
                for install in installations:
                    host_name = install.get('host_name', 'Unknown')
                    host_info = {
                        'name': host_name,
                        'ip': install.get('host_ip', 'N/A'),
                        'os': install.get('host_os', 'Unknown'),
                        'install_date': install.get('install_date', 'Unknown')
                    }
                    
                    # Check if this host is already in the version's host list
                    if not any(h['name'] == host_name for h in results['versions'][version]['hosts']):
                        results['versions'][version]['hosts'].append(host_info)
                    
                    if host_name not in results['hosts_by_version'][version]:
                        results['hosts_by_version'][version].append(host_name)
                    
                    results['installations_by_host'][host_name].append({
                        'software': package.get('name', software_name),
                        'version': version
                    })
        
        results['total_versions'] = len(results['versions'])
        
        return results
    
    def _get_software_installations_optimized(self, software_sys_id: str, limit: int = 100) -> List[Dict]:
        """
        OPTIMIZED: Get installation details for a specific software package.
        Uses batch queries to fetch host details instead of individual queries.
        
        Args:
            software_sys_id: sys_id of the software package
            limit: Maximum number of installations to retrieve
        
        Returns:
            List of installation details
        """
        installations = []
        host_sys_ids = []
        installation_data = []
        
        # Debug: Log which software package we're querying
        if self.debug:
            print(f"  → Getting installations for software sys_id: {software_sys_id}")
        
        # First try cmdb_sam_sw_install table if we haven't been denied access yet
        if not self.sam_access_denied:
            params = {
                'sysparm_query': f'software={software_sys_id}',
                'sysparm_limit': str(limit),
                'sysparm_fields': 'sys_id,installed_on,install_date,install_status,version',
                'sysparm_order_by': 'install_date'
            }
            
            response = self.api_request('/api/now/table/cmdb_sam_sw_install', params)
            
            if response and response.get('result'):
                # First, collect all host sys_ids
                for install in response['result']:
                    host_ref = install.get('installed_on', {})
                    if isinstance(host_ref, dict) and host_ref.get('value'):
                        host_sys_ids.append(host_ref['value'])
                        installation_data.append(install)
                
                # Batch fetch all host details
                if host_sys_ids:
                    if self.debug:
                        print(f"    Batch fetching {len(host_sys_ids)} hosts...")
                    
                    hosts = self._batch_get_hosts(host_sys_ids)
                    
                    # Combine installation data with host details
                    for i, install in enumerate(installation_data):
                        host_ref = install.get('installed_on', {})
                        if isinstance(host_ref, dict) and host_ref.get('value'):
                            host_sys_id = host_ref['value']
                            host_details = hosts.get(host_sys_id, {})
                            
                            installations.append({
                                **host_details,
                                'install_date': install.get('install_date', 'Unknown'),
                                'install_status': install.get('install_status', 'Unknown'),
                                'version': install.get('version', 'Unknown')
                            })
        
        # If no results from SAM table, try relationships
        if not installations:
            if self.debug:
                print(f"  → Falling back to relationship query for sys_id: {software_sys_id}")
            
            params = {
                'sysparm_query': f'child={software_sys_id}^type.name=Installed on::Installs',
                'sysparm_limit': str(limit),
                'sysparm_fields': 'parent,child',
                'sysparm_order_by': 'sys_created_on'
            }
            
            response = self.api_request('/api/now/table/cmdb_rel_ci', params)
            
            if response and response.get('result'):
                # Collect all host sys_ids
                host_sys_ids = []
                for rel in response['result']:
                    parent_ref = rel.get('parent', {})
                    if isinstance(parent_ref, dict) and parent_ref.get('value'):
                        host_sys_ids.append(parent_ref['value'])
                
                # Batch fetch all host details
                if host_sys_ids:
                    if self.debug:
                        print(f"    Batch fetching {len(host_sys_ids)} hosts from relationships...")
                    
                    hosts = self._batch_get_hosts(host_sys_ids)
                    
                    for host_sys_id, host_details in hosts.items():
                        installations.append({
                            **host_details,
                            'install_date': 'Unknown',
                            'install_status': 'Active'
                        })
        
        return installations
    
    def get_software_summary(self, manufacturer: Optional[str] = None, 
                            software_name: Optional[str] = None) -> Dict:
        """
        Get a comprehensive software inventory summary.
        
        Args:
            manufacturer: Optional manufacturer filter
            software_name: Optional software name filter
        
        Returns:
            Summary dictionary with statistics
        """
        summary = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'filters': {
                'manufacturer': manufacturer,
                'software_name': software_name
            },
            'statistics': {},
            'top_software': [],
            'version_distribution': {}
        }
        
        # Build query
        query_parts = []
        if manufacturer:
            query_parts.append(f'manufacturerLIKE{manufacturer}')
        if software_name:
            query_parts.append(f'nameLIKE{software_name}')
        
        query = '^'.join(query_parts) if query_parts else 'install_count>0'
        
        params = {
            'sysparm_query': query,
            'sysparm_limit': '1000',
            'sysparm_fields': 'name,version,manufacturer,vendor,install_count',
            'sysparm_order_by': 'install_count'
        }
        
        response = self.api_request('/api/now/table/cmdb_ci_spkg', params)
        
        if response and response.get('result'):
            packages = response['result']
            
            # Calculate statistics
            total_packages = len(packages)
            total_installations = sum(int(p.get('install_count', 0)) for p in packages)
            
            # Group by software name
            software_groups = defaultdict(lambda: {'versions': [], 'total_installs': 0})
            
            for package in packages:
                name = package.get('name', 'Unknown')
                version = package.get('version', 'Unknown')
                installs = int(package.get('install_count', 0))
                
                software_groups[name]['versions'].append(version)
                software_groups[name]['total_installs'] += installs
            
            # Get top software by installation count
            top_software = sorted(
                [(name, data['total_installs'], len(data['versions'])) 
                 for name, data in software_groups.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            summary['statistics'] = {
                'total_unique_packages': total_packages,
                'total_installations': total_installations,
                'unique_software_products': len(software_groups),
                'average_installs_per_package': round(total_installations / total_packages, 2) if total_packages > 0 else 0
            }
            
            summary['top_software'] = [
                {
                    'name': name,
                    'total_installations': installs,
                    'version_count': versions
                }
                for name, installs, versions in top_software
            ]
            
            # Version distribution for filtered software
            if software_name:
                for package in packages:
                    if software_name.lower() in package.get('name', '').lower():
                        version = package.get('version', 'Unknown')
                        installs = int(package.get('install_count', 0))
                        summary['version_distribution'][version] = installs
        
        return summary
    
    def display_manufacturer_results(self, results: Dict):
        """Display manufacturer search results."""
        if results['total_packages'] == 0:
            return
        
        # Get the company sys_id if we have packages
        company_id = ''
        if results.get('packages') and results['packages'][0].get('manufacturer_id'):
            company_id = results['packages'][0]['manufacturer_id']
        
        print(f"\n{'=' * 80}")
        print(f"📊 SOFTWARE INVENTORY")
        print(f"   Manufacturer: {results['manufacturer']} (ID: {company_id})" if company_id else f"   Manufacturer: {results['manufacturer']}")
        print(f"{'=' * 80}\n")
        
        print(f"📈 SUMMARY:")
        print(f"   Total Software Packages: {results['total_packages']}")
        print(f"   Total Installations: {results['total_installations']}")
        print(f"   Unique Products: {len(results['unique_versions'])}\n")
        
        # Add permission notice if needed
        if self.sam_access_denied:
            print(f"\n⚠️  NOTE: Detailed host information is limited due to permissions.")
            print(f"   Request 'sam_user' or 'asset' role for full installation details.\n")
        
        # Show software breakdown
        print(f"📦 SOFTWARE PRODUCTS:")
        print("-" * 60)
        
        # Sort software by total installations
        sorted_software = sorted(
            [(name, versions) for name, versions in results['unique_versions'].items()],
            key=lambda x: sum(v['count'] for v in x[1].values()),
            reverse=True
        )
        
        # Show top 20 software products
        shown_count = 0
        for software_name, versions in sorted_software:
            total_installs = sum(v['count'] for v in versions.values())
            if total_installs > 0:  # Only show software with actual installations
                print(f"\n{software_name}")
                print(f"   Total Installations: {total_installs}")
                print(f"   Versions Found: {len(versions)}")
                
                # Show version breakdown (top 5)
                for version, details in sorted(versions.items(), 
                                             key=lambda x: x[1]['count'], 
                                             reverse=True)[:5]:
                    if details['count'] > 0:
                        print(f"      • v{version}: {details['count']} devices")
                        if details['hosts'] and len(details['hosts']) <= 3:
                            print(f"        Hosts: {', '.join(details['hosts'][:3])}")
                
                shown_count += 1
                if shown_count >= 20:
                    break
        
        remaining = len([s for s in sorted_software if sum(v['count'] for v in s[1].values()) > 0]) - shown_count
        if remaining > 0:
            print(f"\n   ... and {remaining} more products")
        
        # Export tip
        print(f"\n💾 Use --export flag to save results to CSV and JSON files")
    
    def display_software_results(self, results: Dict):
        """Display software name search results."""
        if results['total_versions'] == 0:
            return
        
        print(f"\n{'=' * 80}")
        print(f"📊 SOFTWARE INVENTORY - {results['software_name']}")
        print(f"{'=' * 80}\n")
        
        print(f"📈 SUMMARY:")
        print(f"   Software: {results['software_name']}")
        print(f"   Total Versions: {results['total_versions']}")
        print(f"   Total Installations: {results['total_installations']}\n")
        
        # Add permission notice if needed
        if self.sam_access_denied:
            print(f"\n⚠️  NOTE: Detailed host information is limited due to permissions.")
            print(f"   Request 'sam_user' or 'asset' role for full installation details.\n")
        
        print(f"📦 VERSION DISTRIBUTION:")
        print("-" * 60)
        
        # Sort versions by installation count
        sorted_versions = sorted(results['versions'].items(), 
                               key=lambda x: x[1]['install_count'], 
                               reverse=True)
        
        for version, details in sorted_versions:
            print(f"\nVersion: {version}")
            print(f"   Manufacturer: {details['manufacturer']}")
            print(f"   Installations: {details['install_count']}")
            
            if details['hosts']:
                print(f"   Sample Hosts ({min(5, len(details['hosts']))} of {len(details['hosts'])}):")
                for host in details['hosts'][:5]:
                    print(f"      • {host['name']} ({host['ip']}) - {host['os']}")
        
        # Export tip
        print(f"\n💾 Use --export flag to save results to CSV and JSON files")
    
    def export_results(self, results: Dict, filename_prefix: str = "software_inventory"):
        """Export results to CSV and JSON files."""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Export to JSON
        json_file = f"{filename_prefix}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Export to CSV based on search type
        csv_file = f"{filename_prefix}_{timestamp}.csv"
        with open(csv_file, 'w') as f:
            if results['search_type'] == 'manufacturer':
                f.write('Software Name,Version,Manufacturer,Install Count,Hosts\n')
                for package in results['packages']:
                    hosts_str = ', '.join([i.get('host_name', 'Unknown') 
                                         for i in package.get('installations', [])[:5]])
                    f.write(f'"{package["name"]}","{package["version"]}",')
                    f.write(f'"{package["manufacturer"]}",{package["install_count"]},')
                    f.write(f'"{hosts_str}"\n')
            
            elif results['search_type'] == 'software_name':
                f.write('Version,Manufacturer,Install Count,Sample Hosts\n')
                for version, details in results['versions'].items():
                    hosts_str = ', '.join([h['name'] for h in details['hosts'][:5]])
                    f.write(f'"{version}","{details["manufacturer"]}",')
                    f.write(f'{details["install_count"]},"{hosts_str}"\n')
        
        # Export detailed host report
        if results.get('installations_by_host'):
            host_file = f"{filename_prefix}_by_host_{timestamp}.csv"
            with open(host_file, 'w') as f:
                f.write('Host Name,Software,Version\n')
                for host, software_list in results['installations_by_host'].items():
                    for sw in software_list:
                        f.write(f'"{host}","{sw["software"]}","{sw["version"]}"\n')
            
            print(f"\n✅ Files exported:")
            print(f"   • {json_file}")
            print(f"   • {csv_file}")
            print(f"   • {host_file}")
        else:
            print(f"\n✅ Files exported:")
            print(f"   • {json_file}")
            print(f"   • {csv_file}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='ServiceNow Software Inventory Analyzer (OPTIMIZED) - Query installed software packages'
    )
    parser.add_argument('--manufacturer', '-m', help='Search by manufacturer (e.g., "Palo Alto Networks", "*axon" for wildcard)')
    parser.add_argument('--software', '-s', help='Search by software name (e.g., "Cortex XDR", "*Office" for wildcard)')
    parser.add_argument('--config', '-c', default='config.json', help='Config file (default: config.json)')
    parser.add_argument('--summary', action='store_true', help='Show summary statistics only')
    parser.add_argument('--no-details', action='store_true', help='Skip fetching installation details (faster)')
    parser.add_argument('--export', action='store_true', help='Export results to files')
    parser.add_argument('--debug', action='store_true', help='Enable debug output for troubleshooting')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.manufacturer and not args.software:
        print("❌ Error: Must specify either --manufacturer or --software")
        parser.print_help()
        sys.exit(1)
    
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
    
    # Create analyzer with debug flag
    analyzer = SoftwareInventoryAnalyzer(**config, debug=args.debug)
    
    # Get fetch_details setting
    fetch_details = not args.no_details
    
    # Show performance tip if fetching details
    if fetch_details:
        print("\n💡 TIP: Use --no-details flag for faster queries (skips host enumeration)")
    
    # Perform search based on arguments
    if args.summary:
        # Get summary statistics
        results = analyzer.get_software_summary(
            manufacturer=args.manufacturer,
            software_name=args.software
        )
        
        print(f"\n📊 SOFTWARE INVENTORY SUMMARY")
        print(f"{'=' * 60}")
        print(f"Filters: Manufacturer={args.manufacturer or 'Any'}, Software={args.software or 'Any'}")
        print(f"\nStatistics:")
        for key, value in results['statistics'].items():
            print(f"   {key.replace('_', ' ').title()}: {value}")
        
        if results['top_software']:
            print(f"\nTop Software by Installations:")
            for i, sw in enumerate(results['top_software'], 1):
                print(f"   {i}. {sw['name']}: {sw['total_installations']} installs ({sw['version_count']} versions)")
        
        if results['version_distribution']:
            print(f"\nVersion Distribution for {args.software}:")
            for version, count in sorted(results['version_distribution'].items(), 
                                        key=lambda x: x[1], reverse=True):
                print(f"   v{version}: {count} installations")
    
    elif args.manufacturer:
        # Search by manufacturer
        results = analyzer.search_by_manufacturer(args.manufacturer, fetch_details)
        analyzer.display_manufacturer_results(results)
        
        if args.export and results['total_packages'] > 0:
            prefix = f"software_{args.manufacturer.replace(' ', '_').lower()}"
            analyzer.export_results(results, prefix)
    
    elif args.software:
        # Search by software name
        results = analyzer.search_by_software_name(args.software, fetch_details)
        analyzer.display_software_results(results)
        
        if args.export and results['total_versions'] > 0:
            prefix = f"software_{args.software.replace(' ', '_').lower()}"
            analyzer.export_results(results, prefix)
    
    # Show cache statistics in debug mode
    if args.debug:
        print(f"\n📊 Cache Statistics:")
        print(f"   Cached hosts: {len(analyzer.host_cache)}")
        print(f"   Cached companies: {len(analyzer.company_cache)}")


if __name__ == "__main__":
    main()