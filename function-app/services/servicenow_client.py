"""
ServiceNow Vulnerability Analysis Client
Refactored for Azure Functions with Enhanced Logging
"""

import requests
import time
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict
from datetime import datetime, timedelta
from .logging_utils import log_servicenow_operation

logger = logging.getLogger(__name__)


class ServiceNowClient:
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
        self.company_cache = {}  # Cache for company name lookups
        self.sam_access_denied = False
        self.permission_warnings = set()
        
        # Enhanced logging context
        logger.info("ServiceNow client initialized", extra={
            'custom_dimensions': {
                'instance_url': self.instance_url,
                'client_id': self.client_id[:8] + '***',  # Partial for identification
                'username': self.username,
                'timestamp': datetime.utcnow().isoformat()
            }
        })
        
    @log_servicenow_operation("get_oauth_token")
    def get_oauth_token(self) -> str:
        """Get OAuth2 access token with enhanced logging."""
        if self.access_token and time.time() < self.token_expiry:
            logger.debug("Using cached OAuth token", extra={
                'custom_dimensions': {
                    'token_expiry': self.token_expiry,
                    'current_time': time.time(),
                    'time_remaining': self.token_expiry - time.time()
                }
            })
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
        
        logger.info("Requesting OAuth token", extra={
            'custom_dimensions': {
                'token_url': token_url,
                'username': self.username,
                'grant_type': 'password'
            }
        })
        
        start_time = time.time()
        
        try:
            response = requests.post(token_url, data=data, headers=headers, timeout=30)
            duration = time.time() - start_time
            
            logger.info("OAuth token request completed", extra={
                'custom_dimensions': {
                    'status_code': response.status_code,
                    'duration_ms': round(duration * 1000, 2),
                    'response_size': len(response.content)
                }
            })
            
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            duration = time.time() - start_time
            logger.error(f"Authentication failed: {e}", extra={
                'custom_dimensions': {
                    'error': str(e),
                    'duration_ms': round(duration * 1000, 2),
                    'token_url': token_url,
                    'username': self.username
                }
            })
            raise Exception(f"ServiceNow authentication failed: {str(e)}")
        
        token_data = response.json()
        self.access_token = token_data['access_token']
        expires_in = token_data.get('expires_in', 1800)
        self.token_expiry = time.time() + expires_in - 300  # 5 min buffer
        
        logger.info("OAuth token obtained successfully", extra={
            'custom_dimensions': {
                'expires_in': expires_in,
                'token_expiry': self.token_expiry,
                'token_length': len(self.access_token)
            }
        })
        
        return self.access_token
    
    @log_servicenow_operation("api_request")
    def api_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make authenticated API request with comprehensive logging."""
        start_time = time.time()
        
        logger.debug(f"Making API request to {endpoint}", extra={
            'custom_dimensions': {
                'endpoint': endpoint,
                'params': params,
                'has_params': params is not None,
                'param_count': len(params) if params else 0
            }
        })
        
        token = self.get_oauth_token()
        url = f"{self.instance_url}{endpoint}"
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=60)
            duration = time.time() - start_time
            
            # Log response details
            logger.info(f"API request completed: {endpoint}", extra={
                'custom_dimensions': {
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'duration_ms': round(duration * 1000, 2),
                    'response_size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'unknown')
                }
            })
            
            if response.status_code == 400:
                logger.warning(f"Bad request for {endpoint}", extra={
                    'custom_dimensions': {
                        'endpoint': endpoint,
                        'params': params,
                        'response_text': response.text[:500]  # First 500 chars
                    }
                })
                return None
                
            if response.status_code == 403:
                # Track permission issues for specific tables
                table_name = endpoint.split('/')[-1] if '/' in endpoint else endpoint
                
                if 'cmdb_sam_sw_install' in endpoint:
                    self.sam_access_denied = True
                    if 'cmdb_sam_sw_install' not in self.permission_warnings:
                        self.permission_warnings.add('cmdb_sam_sw_install')
                        logger.warning("Permission denied for cmdb_sam_sw_install table. Requires 'sam_user' or 'asset' role.", extra={
                            'custom_dimensions': {
                                'endpoint': endpoint,
                                'table': 'cmdb_sam_sw_install',
                                'required_roles': ['sam_user', 'asset']
                            }
                        })
                else:
                    logger.warning(f"Access denied to {endpoint} - insufficient permissions", extra={
                        'custom_dimensions': {
                            'endpoint': endpoint,
                            'table': table_name,
                            'status_code': 403
                        }
                    })
                return None
                
            response.raise_for_status()
            
            # Parse and validate response
            response_data = response.json()
            result_count = len(response_data.get('result', [])) if isinstance(response_data.get('result'), list) else (1 if response_data.get('result') else 0)
            
            logger.info(f"API request successful: {endpoint}", extra={
                'custom_dimensions': {
                    'endpoint': endpoint,
                    'result_count': result_count,
                    'has_result': 'result' in response_data,
                    'response_keys': list(response_data.keys()) if isinstance(response_data, dict) else []
                }
            })
            
            return response_data
            
        except requests.exceptions.Timeout as e:
            duration = time.time() - start_time
            logger.error(f"API request timeout: {endpoint}", extra={
                'custom_dimensions': {
                    'endpoint': endpoint,
                    'duration_ms': round(duration * 1000, 2),
                    'error': 'timeout',
                    'timeout_seconds': 60
                }
            })
            return None
            
        except requests.exceptions.RequestException as e:
            duration = time.time() - start_time
            
            if '403' in str(e):
                table_name = endpoint.split('/')[-1] if '/' in endpoint else endpoint
                if 'cmdb_sam_sw_install' in endpoint:
                    self.sam_access_denied = True
                    if 'cmdb_sam_sw_install' not in self.permission_warnings:
                        self.permission_warnings.add('cmdb_sam_sw_install')
                        logger.warning("Permission denied for cmdb_sam_sw_install table. Requires 'sam_user' or 'asset' role.", extra={
                            'custom_dimensions': {
                                'endpoint': endpoint,
                                'table': 'cmdb_sam_sw_install',
                                'error': str(e)
                            }
                        })
                else:
                    logger.error(f"API request failed with 403: {endpoint}", extra={
                        'custom_dimensions': {
                            'endpoint': endpoint,
                            'error': str(e),
                            'table': table_name,
                            'duration_ms': round(duration * 1000, 2)
                        }
                    })
            else:
                logger.error(f"API request failed: {endpoint}", extra={
                    'custom_dimensions': {
                        'endpoint': endpoint,
                        'error': str(e),
                        'error_type': type(e).__name__,
                        'duration_ms': round(duration * 1000, 2)
                    }
                })
            return None
            
        except ValueError as e:
            duration = time.time() - start_time
            logger.error(f"JSON parsing error for {endpoint}", extra={
                'custom_dimensions': {
                    'endpoint': endpoint,
                    'error': str(e),
                    'duration_ms': round(duration * 1000, 2),
                    'response_preview': response.text[:200] if 'response' in locals() else 'No response'
                }
            })
            return None
    
    @log_servicenow_operation("get_company_name")
    def get_company_name(self, company_sys_id: str) -> str:
        """
        Get the company name for a given sys_id from the core_company table.
        Enhanced with caching and logging.
        """
        logger.debug(f"Retrieving company name for sys_id: {company_sys_id}")
        
        # Check cache first
        if company_sys_id in self.company_cache:
            logger.debug(f"Company name found in cache: {company_sys_id}", extra={
                'custom_dimensions': {
                    'company_sys_id': company_sys_id,
                    'cache_hit': True,
                    'cached_name': self.company_cache[company_sys_id]
                }
            })
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
            
            logger.info(f"Company name retrieved and cached: {name}", extra={
                'custom_dimensions': {
                    'company_sys_id': company_sys_id,
                    'company_name': name,
                    'cache_size': len(self.company_cache)
                }
            })
            
            return name
        
        logger.warning(f"Company not found for sys_id: {company_sys_id}", extra={
            'custom_dimensions': {
                'company_sys_id': company_sys_id,
                'response_empty': True
            }
        })
        
        return ''
    
    @log_servicenow_operation("get_company_sys_id")
    def get_company_sys_id(self, company_name: str) -> Optional[str]:
        """
        Get the sys_id for a company/manufacturer from the core_company table.
        Enhanced with logging.
        """
        logger.debug(f"Searching for company sys_id: {company_name}")
        
        # Use LIKE query to find the company
        params = {
            'sysparm_query': f'nameLIKE{company_name}',
            'sysparm_limit': '10',
            'sysparm_fields': 'sys_id,name'
        }
        
        response = self.api_request('/api/now/table/core_company', params)
        
        if response and response.get('result'):
            results = response['result']
            
            logger.debug(f"Found {len(results)} potential companies for '{company_name}'", extra={
                'custom_dimensions': {
                    'search_term': company_name,
                    'results_count': len(results),
                    'results': [{'sys_id': r['sys_id'], 'name': r.get('name', '')} for r in results]
                }
            })
            
            # Look for exact match first
            for company in results:
                if company.get('name', '').lower() == company_name.lower():
                    logger.info(f"Exact company match found: {company['name']}", extra={
                        'custom_dimensions': {
                            'search_term': company_name,
                            'match_type': 'exact',
                            'company_sys_id': company['sys_id'],
                            'company_name': company['name']
                        }
                    })
                    return company['sys_id']
                    
            # If no exact match, return the first result
            if results:
                first_result = results[0]
                logger.info(f"Using first partial match: {first_result.get('name', '')}", extra={
                    'custom_dimensions': {
                        'search_term': company_name,
                        'match_type': 'partial',
                        'company_sys_id': first_result['sys_id'],
                        'company_name': first_result.get('name', '')
                    }
                })
                return first_result['sys_id']
        
        logger.warning(f"No company found for: {company_name}", extra={
            'custom_dimensions': {
                'search_term': company_name,
                'results_count': 0
            }
        })
        
        return None


class VulnerabilityAnalyzer:
    def __init__(self, client: ServiceNowClient):
        """Initialize analyzer with ServiceNow client."""
        self.client = client
        self.logger = logging.getLogger(f"{__name__}.VulnerabilityAnalyzer")
        
        self.logger.info("VulnerabilityAnalyzer initialized", extra={
            'custom_dimensions': {
                'client_instance': self.client.instance_url,
                'timestamp': datetime.utcnow().isoformat()
            }
        })
        
    @log_servicenow_operation("analyze_vulnerability")
    def analyze_vulnerability(self, vuln_id: str, fetch_all_details: bool = False, 
                            include_patched: bool = False, 
                            confirmation_state: str = None) -> Dict:
        """
        Analyze CVE or QID and count vulnerable systems.
        Enhanced with comprehensive logging.
        """
        start_time = time.time()
        
        self.logger.info(f"Starting vulnerability analysis for: {vuln_id}", extra={
            'custom_dimensions': {
                'vuln_id': vuln_id,
                'fetch_all_details': fetch_all_details,
                'include_patched': include_patched,
                'confirmation_state': confirmation_state,
                'analysis_start': datetime.utcnow().isoformat()
            }
        })
        
        # Determine vulnerability type
        if vuln_id.upper().startswith('QID-'):
            vuln_type = 'QID'
            qid_number = vuln_id[4:]
        elif vuln_id.isdigit():
            vuln_type = 'QID'
            qid_number = vuln_id
            vuln_id = f'QID-{vuln_id}'
        else:
            vuln_type = 'CVE'
            qid_number = None
        
        self.logger.info(f"Vulnerability type determined: {vuln_type}", extra={
            'custom_dimensions': {
                'vuln_id': vuln_id,
                'vuln_type': vuln_type,
                'qid_number': qid_number
            }
        })
        
        results = {
            'vuln_id': vuln_id,
            'vuln_type': vuln_type,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'found': False,
            'total_vulnerable_systems': 0,
            'systems': []
        }
        
        # Process based on type
        if vuln_type == 'QID':
            results = self._analyze_qid(qid_number, results)
        else:
            results = self._analyze_cve(vuln_id, results)
        
        if not results['found']:
            self.logger.warning(f"Vulnerability not found: {vuln_id}", extra={
                'custom_dimensions': {
                    'vuln_id': vuln_id,
                    'vuln_type': vuln_type,
                    'search_duration_ms': round((time.time() - start_time) * 1000, 2)
                }
            })
            return results
        
        self.logger.info(f"Vulnerability found, fetching vulnerable items: {vuln_id}", extra={
            'custom_dimensions': {
                'vuln_id': vuln_id,
                'vuln_type': vuln_type,
                'metadata_retrieval_duration_ms': round((time.time() - start_time) * 1000, 2)
            }
        })
        
        # Get vulnerable items
        results = self._get_vulnerable_items(
            results, 
            fetch_all_details, 
            include_patched, 
            confirmation_state
        )
        
        total_duration = time.time() - start_time
        
        self.logger.info(f"Vulnerability analysis completed: {vuln_id}", extra={
            'custom_dimensions': {
                'vuln_id': vuln_id,
                'vuln_type': vuln_type,
                'found': results['found'],
                'total_vulnerable_systems': results.get('total_vulnerable_systems', 0),
                'systems_retrieved': len(results.get('systems', [])),
                'total_duration_ms': round(total_duration * 1000, 2),
                'analysis_end': datetime.utcnow().isoformat()
            }
        })
        
        return results
    
    @log_servicenow_operation("analyze_qid")
    def _analyze_qid(self, qid_number: str, results: Dict) -> Dict:
        """Analyze QID vulnerability with enhanced logging."""
        self.logger.debug(f"Analyzing QID: QID-{qid_number}")
        
        params = {
            'sysparm_query': f'id=QID-{qid_number}',
            'sysparm_limit': '1'
        }
        
        third_party_result = self.client.api_request('/api/now/table/sn_vul_third_party_entry', params)
        
        if not third_party_result or not third_party_result.get('result'):
            self.logger.warning(f"QID-{qid_number} not found in third_party_entry table", extra={
                'custom_dimensions': {
                    'qid_number': qid_number,
                    'table': 'sn_vul_third_party_entry',
                    'query': f'id=QID-{qid_number}'
                }
            })
            return results
        
        third_party_entries = third_party_result['result']
        results['found'] = True
        results['third_party_entries'] = third_party_entries
        
        # Get metadata
        tp_entry = third_party_entries[0]
        results['source'] = tp_entry.get('source', 'Qualys')
        results['summary'] = tp_entry.get('summary', tp_entry.get('description', 'N/A'))
        results['cvss_score'] = tp_entry.get('cvss_base_score', 'N/A')
        
        # Get associated CVEs
        cves_list = tp_entry.get('cves_list', '')
        if cves_list:
            results['associated_cves'] = cves_list
        
        self.logger.info(f"QID analysis completed: QID-{qid_number}", extra={
            'custom_dimensions': {
                'qid_number': qid_number,
                'source': results['source'],
                'cvss_score': results['cvss_score'],
                'has_associated_cves': bool(cves_list),
                'associated_cves_count': len(cves_list.split(',')) if cves_list else 0
            }
        })
        
        return results
    
    @log_servicenow_operation("analyze_cve")
    def _analyze_cve(self, cve_id: str, results: Dict) -> Dict:
        """Analyze CVE vulnerability with enhanced logging."""
        self.logger.debug(f"Analyzing CVE: {cve_id}")
        
        # Find CVE in NVD entries
        params = {
            'sysparm_query': f'id={cve_id}',
            'sysparm_limit': '1'
        }
        
        nvd_result = self.client.api_request('/api/now/table/sn_vul_nvd_entry', params)
        
        if not nvd_result or not nvd_result.get('result'):
            self.logger.warning(f"CVE {cve_id} not found in nvd_entry table", extra={
                'custom_dimensions': {
                    'cve_id': cve_id,
                    'table': 'sn_vul_nvd_entry',
                    'query': f'id={cve_id}'
                }
            })
            return results
        
        nvd_entry = nvd_result['result'][0]
        results['found'] = True
        results['cvss_score'] = nvd_entry.get('v3_base_score', 'N/A')
        results['summary'] = nvd_entry.get('summary', 'N/A')
        results['published'] = str(nvd_entry.get('date_published', 'N/A'))
        
        # Find third-party entries
        cve_sys_id = nvd_entry.get('sys_id')
        params = {
            'sysparm_query': f'cves_listLIKE{cve_sys_id}',
            'sysparm_limit': '100'
        }
        
        third_party_result = self.client.api_request('/api/now/table/sn_vul_third_party_entry', params)
        
        third_party_count = 0
        if third_party_result and third_party_result.get('result'):
            results['third_party_entries'] = third_party_result['result']
            third_party_count = len(third_party_result['result'])
        
        self.logger.info(f"CVE analysis completed: {cve_id}", extra={
            'custom_dimensions': {
                'cve_id': cve_id,
                'cvss_score': results['cvss_score'],
                'published': results['published'],
                'third_party_entries_count': third_party_count,
                'cve_sys_id': cve_sys_id
            }
        })
        
        return results
    
    @log_servicenow_operation("get_vulnerable_items")
    def _get_vulnerable_items(self, results: Dict, fetch_all_details: bool,
                             include_patched: bool, confirmation_state: str) -> Dict:
        """Get vulnerable items and system details with comprehensive logging."""
        if 'third_party_entries' not in results:
            self.logger.warning("No third_party_entries found for vulnerable items query")
            return results
        
        third_party_entries = results['third_party_entries']
        
        self.logger.info("Starting vulnerable items retrieval", extra={
            'custom_dimensions': {
                'vuln_id': results['vuln_id'],
                'third_party_entries_count': len(third_party_entries),
                'fetch_all_details': fetch_all_details,
                'include_patched': include_patched,
                'confirmation_state': confirmation_state
            }
        })
        
        # Calculate totals
        total_active = sum(int(tp.get('count_active_vi', 0)) for tp in third_party_entries)
        total_all_time = sum(int(tp.get('total_vis', 0)) for tp in third_party_entries)
        
        results['total_vulnerable_systems'] = total_active
        results['total_all_time'] = total_all_time
        results['confirmation_filter'] = confirmation_state
        
        self.logger.info("Calculated vulnerability totals", extra={
            'custom_dimensions': {
                'vuln_id': results['vuln_id'],
                'total_active': total_active,
                'total_all_time': total_all_time,
                'active_percentage': round((total_active / total_all_time * 100), 2) if total_all_time > 0 else 0
            }
        })
        
        if total_active == 0:
            self.logger.info("No active vulnerable systems found")
            return results
        
        # Determine fetch limit
        if fetch_all_details or total_active <= 100:
            limit_per_query = min(1000, total_active)
            sample_only = False
        else:
            limit_per_query = 50
            sample_only = True
        
        self.logger.info("Fetch strategy determined", extra={
            'custom_dimensions': {
                'vuln_id': results['vuln_id'],
                'limit_per_query': limit_per_query,
                'sample_only': sample_only,
                'fetch_all_details': fetch_all_details,
                'total_active': total_active
            }
        })
        
        systems = []
        seen_systems = set()
        
        # Map confirmation states
        confirmation_map = {
            'confirmed': '1',
            'potential': ['2', '3', '4'],
            'potential-investigation': '2',
            'potential-patch': '3',
            'potential-low': '4'
        }
        
        query_count = 0
        
        for tp in third_party_entries:
            query_count += 1
            tp_sys_id = tp.get('sys_id')
            
            self.logger.debug(f"Processing third-party entry {query_count}/{len(third_party_entries)}: {tp_sys_id}")
            
            # Build query
            query_parts = [f'vulnerability={tp_sys_id}']
            
            if not include_patched:
                query_parts.append('active=true')
                query_parts.append('state=1')  # Only Open state vulnerabilities
            
            # Add confirmation state filter
            if confirmation_state and confirmation_state in confirmation_map:
                conf_value = confirmation_map[confirmation_state]
                if isinstance(conf_value, list):
                    conf_queries = [f'u_confirmed_potential={v}' for v in conf_value]
                    query_parts.append(f"({'^OR'.join(conf_queries)})")
                else:
                    query_parts.append(f'u_confirmed_potential={conf_value}')
            elif confirmation_state == 'none':
                query_parts.append('u_confirmed_potentialISEMPTY')
            
            query = '^'.join(query_parts)
            
            params = {
                'sysparm_query': query,
                'sysparm_limit': str(limit_per_query),
                'sysparm_fields': 'sys_id,number,cmdb_ci,short_description,active,state,u_confirmed_potential,assignment_group'
            }
            
            self.logger.debug(f"Querying vulnerable_item table with query: {query[:100]}...")
            
            vi_start_time = time.time()
            vi_result = self.client.api_request('/api/now/table/sn_vul_vulnerable_item', params)
            vi_duration = time.time() - vi_start_time
            
            if vi_result and vi_result.get('result'):
                vi_count = len(vi_result['result'])
                
                self.logger.info(f"Retrieved {vi_count} vulnerable items from third-party entry", extra={
                    'custom_dimensions': {
                        'vuln_id': results['vuln_id'],
                        'tp_sys_id': tp_sys_id,
                        'vi_count': vi_count,
                        'query_duration_ms': round(vi_duration * 1000, 2),
                        'query_number': query_count
                    }
                })
                
                systems_processed = 0
                
                for vi in vi_result['result']:
                    ci_ref = vi.get('cmdb_ci', {})
                    
                    if isinstance(ci_ref, dict) and ci_ref.get('value'):
                        ci_id = ci_ref['value']
                        
                        if ci_id not in seen_systems:
                            systems_processed += 1
                            seen_systems.add(ci_id)
                            
                            # Get CI details
                            ci_start_time = time.time()
                            ci_result = self.client.api_request(f'/api/now/table/cmdb_ci/{ci_id}')
                            ci_duration = time.time() - ci_start_time
                            
                            if ci_result and ci_result.get('result'):
                                ci = ci_result['result']
                                
                                # Get assignment group name if available
                                assignment_group_name = 'N/A'
                                ag_ref = vi.get('assignment_group', {})
                                if isinstance(ag_ref, dict) and ag_ref.get('value'):
                                    ag_id = ag_ref['value']
                                    ag_result = self.client.api_request(f'/api/now/table/sys_user_group/{ag_id}')
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
                                
                                if systems_processed % 10 == 0:
                                    self.logger.debug(f"Processed {systems_processed} systems so far...")
                            
                            if sample_only and len(systems) >= limit_per_query:
                                self.logger.info("Sample limit reached, stopping system retrieval")
                                break
                
                self.logger.info(f"Completed processing third-party entry {query_count}", extra={
                    'custom_dimensions': {
                        'vuln_id': results['vuln_id'],
                        'tp_sys_id': tp_sys_id,
                        'systems_processed': systems_processed,
                        'total_systems_so_far': len(systems)
                    }
                })
            else:
                self.logger.warning(f"No vulnerable items found for third-party entry: {tp_sys_id}")
        
        results['systems'] = systems
        results['systems_retrieved'] = len(systems)
        results['sample_only'] = sample_only
        
        if confirmation_state:
            results['filtered_vulnerable_systems'] = len(seen_systems)
        
        self.logger.info("Vulnerable items retrieval completed", extra={
            'custom_dimensions': {
                'vuln_id': results['vuln_id'],
                'total_systems_retrieved': len(systems),
                'unique_systems': len(seen_systems),
                'sample_only': sample_only,
                'queries_executed': query_count,
                'confirmation_filter_applied': confirmation_state is not None
            }
        })
        
        return results
    
    def search_by_confirmation_status(self, confirmation_state: str, days: int = 14, 
                                     fetch_all_details: bool = False) -> Dict:
        """
        Search for vulnerabilities with specific confirmation status.
        
        Args:
            confirmation_state: Confirmation state to search for
            days: Number of days to look back
            fetch_all_details: If True, fetch all details
        
        Returns:
            Dictionary with search results
        """
        logger.info(f"Searching for {confirmation_state} vulnerabilities from last {days} days")
        
        # Map confirmation states
        confirmation_map = {
            'confirmed': '1',
            'potential': ['2', '3', '4'],
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
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_date_str = start_date.strftime('%Y-%m-%d')
        
        # Build query
        query_parts = []
        query_parts.append(f'first_found>={start_date_str}')
        query_parts.append('active=true')
        query_parts.append('state=1')  # Only Open state vulnerabilities
        
        # Add confirmation state filter
        if confirmation_state and confirmation_state in confirmation_map:
            conf_value = confirmation_map[confirmation_state]
            if isinstance(conf_value, list):
                conf_queries = [f'u_confirmed_potential={v}' for v in conf_value]
                query_parts.append(f"({'^OR'.join(conf_queries)})")
            else:
                query_parts.append(f'u_confirmed_potential={conf_value}')
        elif confirmation_state == 'none':
            query_parts.append('u_confirmed_potentialISEMPTY')
        
        query = '^'.join(query_parts)
        
        # Fetch vulnerable items
        limit = 1000 if fetch_all_details else 500
        params = {
            'sysparm_query': query,
            'sysparm_limit': str(limit),
            'sysparm_fields': 'sys_id,number,vulnerability,cmdb_ci,short_description,first_found,ip_address,dns,risk_score,u_confirmed_potential,state,assignment_group'
        }
        
        vi_result = self.client.api_request('/api/now/table/sn_vul_vulnerable_item', params)
        
        if not vi_result or not vi_result.get('result'):
            logger.warning("No vulnerabilities found matching criteria")
            return results
        
        vulnerable_items = vi_result['result']
        results['total_vulnerable_items'] = len(vulnerable_items)
        
        # Group by vulnerability
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
                            ag_result = self.client.api_request(f'/api/now/table/sys_user_group/{ag_id}')
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
        
        # Get details for each vulnerability (limit to 100)
        for vuln_sys_id, items in list(vuln_groups.items())[:100]:
            vuln_result = self.client.api_request(f'/api/now/table/sn_vul_entry/{vuln_sys_id}')
            
            if vuln_result and vuln_result.get('result'):
                vuln_entry = vuln_result['result']
                
                # Check if it's a third-party entry
                tp_result = self.client.api_request('/api/now/table/sn_vul_third_party_entry', {
                    'sysparm_query': f'sys_id={vuln_sys_id}',
                    'sysparm_limit': '1'
                })
                
                vuln_info = {
                    'sys_id': vuln_sys_id,
                    'id': vuln_entry.get('id', 'Unknown'),
                    'summary': vuln_entry.get('summary', vuln_entry.get('description', 'N/A')),
                    'cvss_score': vuln_entry.get('cvss_base_score', vuln_entry.get('v3_base_score', 'N/A')),
                    'affected_systems': len(items),
                    'items': items[:10],
                    'cve_ids': []
                }
                
                # Get QID and CVEs if third-party entry
                if tp_result and tp_result.get('result'):
                    tp_entry = tp_result['result'][0]
                    vuln_info['id'] = tp_entry.get('id', vuln_info['id'])
                    vuln_info['source'] = tp_entry.get('source', 'Unknown')
                    
                    # Get associated CVEs
                    cves_list = tp_entry.get('cves_list', '')
                    if cves_list:
                        if ',' in cves_list:
                            cve_sys_ids = [cve_id.strip() for cve_id in cves_list.split(',') if cve_id.strip()]
                        else:
                            cve_sys_ids = [cves_list.strip()] if cves_list.strip() else []
                        
                        cve_ids = []
                        for cve_sys_id in cve_sys_ids[:5]:  # Limit to 5 CVEs
                            if cve_sys_id and len(cve_sys_id) == 32:
                                cve_result = self.client.api_request(f'/api/now/table/sn_vul_nvd_entry/{cve_sys_id}')
                                if cve_result and cve_result.get('result'):
                                    cve_entry = cve_result['result']
                                    cve_id = cve_entry.get('id', '')
                                    if cve_id and cve_id.startswith('CVE-'):
                                        cve_ids.append(cve_id)
                        
                        vuln_info['cve_ids'] = cve_ids
                
                results['vulnerabilities'].append(vuln_info)
        
        return results