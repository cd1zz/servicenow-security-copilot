"""
Azure Function: Software Inventory
HTTP triggered function to query software inventory from cmdb_ci_spkg
Enhanced with comprehensive logging for debugging
"""

import azure.functions as func
import json
import logging
import os
import time
from typing import Dict, Any, List, Optional
from collections import defaultdict

from services import ServiceNowClient
from services.logging_utils import FunctionLogger

# Configure logger for this function
function_logger = FunctionLogger(__name__)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP trigger function to search software inventory.
    
    Expected JSON body:
    {
        "search_type": "manufacturer" or "software",
        "manufacturer": "Palo Alto Networks",  # if search_type is manufacturer
        "software_name": "Cortex XDR",          # if search_type is software
        "fetch_details": true,                  # optional, default true
        "limit": 100,                           # optional, max results
        "max_hosts_per_version": 25,            # optional, default 25, max hosts to fetch per version
        "performance_mode": "balanced"          # optional: "fast", "balanced", or "full" (default: "balanced")
    }
    """
    # Start request logging
    function_logger.start_request(req, {
        'function_name': 'software-inventory',
        'function_version': '2.0'
    })
    
    try:
        # Validate API key
        api_key = req.headers.get('X-API-Key')
        expected_key = os.environ.get('API_KEY')
        
        if expected_key and api_key != expected_key:
            function_logger.log_warning("Invalid API key provided")
            response = func.HttpResponse(
                json.dumps({"error": "Invalid API key"}),
                status_code=401,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'auth_failure': True})
            return response
        
        # Parse request body
        try:
            req_body = req.get_json()
            function_logger.log_debug("Request body parsed successfully", {
                'body_keys': list(req_body.keys()) if req_body else []
            })
        except ValueError as e:
            function_logger.log_error(e, {'parsing_stage': 'request_body'})
            response = func.HttpResponse(
                json.dumps({"error": "Invalid JSON in request body"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'json_parse_error': True})
            return response
        
        # Validate parameters
        search_type = req_body.get('search_type')
        if search_type not in ['manufacturer', 'software']:
            function_logger.log_warning("Invalid search_type", {
                'provided_search_type': search_type,
                'valid_types': ['manufacturer', 'software']
            })
            response = func.HttpResponse(
                json.dumps({"error": "search_type must be 'manufacturer' or 'software'"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'invalid_search_type'})
            return response
        
        # Get search parameters
        manufacturer = req_body.get('manufacturer')
        software_name = req_body.get('software_name')
        fetch_details = req_body.get('fetch_details', True)
        limit = min(req_body.get('limit', 1000), 1000)  # Cap at 1000
        max_hosts_per_version = min(req_body.get('max_hosts_per_version', 25), 100)  # Default 25, max 100
        performance_mode = req_body.get('performance_mode', 'balanced')
        
        # Validate and adjust parameters based on performance mode
        valid_modes = ['fast', 'balanced', 'full']
        if performance_mode not in valid_modes:
            function_logger.log_warning("Invalid performance_mode, defaulting to balanced", {
                'provided_mode': performance_mode,
                'valid_modes': valid_modes
            })
            performance_mode = 'balanced'
        
        # Adjust settings based on performance mode
        if performance_mode == 'fast':
            # Fast mode: counts only, no host details
            fetch_details = False
            max_hosts_per_version = 0
            function_logger.log_info("Using FAST mode: counts only, no host details")
        elif performance_mode == 'full':
            # Full mode: get all details (up to limit)
            fetch_details = True
            max_hosts_per_version = min(100, limit)  # Get more hosts per version
            function_logger.log_info("Using FULL mode: fetching all available details")
        else:
            # Balanced mode: limited sampling (default)
            fetch_details = True
            max_hosts_per_version = min(max_hosts_per_version, 25)
            function_logger.log_info("Using BALANCED mode: limited sampling for performance")
        
        # Validate search criteria
        if search_type == 'manufacturer' and not manufacturer:
            function_logger.log_warning("Missing manufacturer parameter for manufacturer search")
            response = func.HttpResponse(
                json.dumps({"error": "manufacturer is required when search_type is 'manufacturer'"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'missing_manufacturer'})
            return response
        
        if search_type == 'software' and not software_name:
            function_logger.log_warning("Missing software_name parameter for software search")
            response = func.HttpResponse(
                json.dumps({"error": "software_name is required when search_type is 'software'"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'missing_software_name'})
            return response
        
        function_logger.log_business_event('SOFTWARE_INVENTORY_PARAMETERS', {
            'search_type': search_type,
            'manufacturer': manufacturer,
            'software_name': software_name,
            'fetch_details': fetch_details,
            'limit': limit,
            'max_hosts_per_version': max_hosts_per_version,
            'performance_mode': performance_mode
        })
        
        # Initialize ServiceNow client
        function_logger.log_debug("Initializing ServiceNow client")
        client_start_time = time.time()
        
        try:
            client = create_servicenow_client()
            client_init_duration = time.time() - client_start_time
            
            function_logger.log_business_event('SERVICENOW_CLIENT_INITIALIZED', {
                'initialization_duration_ms': round(client_init_duration * 1000, 2)
            })
            
        except Exception as e:
            function_logger.log_error(e, {
                'initialization_stage': 'servicenow_client',
                'duration_ms': round((time.time() - client_start_time) * 1000, 2)
            })
            response = func.HttpResponse(
                json.dumps({"error": f"ServiceNow client initialization failed: {str(e)}"}),
                status_code=500,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'client_init_error': True})
            return response
        
        # Perform search
        function_logger.log_business_event('SOFTWARE_INVENTORY_SEARCH_START', {
            'search_type': search_type,
            'search_term': manufacturer if search_type == 'manufacturer' else software_name
        })
        
        search_start_time = time.time()
        
        try:
            if search_type == 'manufacturer':
                results = search_by_manufacturer(client, manufacturer, fetch_details, limit, max_hosts_per_version)
            else:
                results = search_by_software(client, software_name, fetch_details, limit, max_hosts_per_version)
                
            search_duration = time.time() - search_start_time
            
            function_logger.log_business_event('SOFTWARE_INVENTORY_SEARCH_COMPLETE', {
                'search_type': search_type,
                'search_duration_ms': round(search_duration * 1000, 2),
                'total_packages': results.get('total_packages', 0),
                'total_installations': results.get('total_installations', 0),
                'software_products_count': len(results.get('software_products', {})),
                'search_status': results.get('status', 'unknown')
            })
            
        except Exception as e:
            search_duration = time.time() - search_start_time
            function_logger.log_error(e, {
                'search_stage': 'software_inventory_search',
                'search_type': search_type,
                'duration_ms': round(search_duration * 1000, 2)
            })
            response = func.HttpResponse(
                json.dumps({"error": f"Software inventory search failed: {str(e)}"}),
                status_code=500,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'search_error': True})
            return response
        
        # Add metadata about the query
        results['metadata'] = {
            'fetch_details': fetch_details,
            'max_hosts_per_version': max_hosts_per_version if fetch_details else 0,
            'note': 'Host details are limited to improve performance. Use max_hosts_per_version parameter to adjust (max 100).'
        }
        
        # Add permission warnings if any
        if client.permission_warnings:
            results['permission_warnings'] = list(client.permission_warnings)
            function_logger.log_warning("Permission warnings detected", {
                'permission_warnings': list(client.permission_warnings)
            })
        
        # Create successful response
        response = func.HttpResponse(
            json.dumps(results, default=str),
            status_code=200,
            mimetype="application/json"
        )
        
        function_logger.end_request(response, {
            'search_type': search_type,
            'search_results_summary': {
                'total_packages': results.get('total_packages', 0),
                'total_installations': results.get('total_installations', 0)
            }
        })
        
        return response
        
    except Exception as e:
        function_logger.log_error(e, {
            'error_stage': 'unexpected_error',
            'error_type': type(e).__name__
        })
        
        response = func.HttpResponse(
            json.dumps({"error": f"Unexpected error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )
        
        function_logger.end_request(response, {'unexpected_error': True})
        return response


def create_servicenow_client() -> ServiceNowClient:
    """Create ServiceNow client with credentials from environment."""
    instance_url = os.environ.get('SERVICENOW_INSTANCE_URL')
    client_id = os.environ.get('SERVICENOW_CLIENT_ID')
    client_secret = os.environ.get('SERVICENOW_CLIENT_SECRET')
    username = os.environ.get('SERVICENOW_USERNAME')
    password = os.environ.get('SERVICENOW_PASSWORD')
    
    if not all([instance_url, client_id, client_secret, username, password]):
        function_logger.log_error(ValueError("Missing ServiceNow credentials"), {
            'missing_credentials': [
                key for key, val in {
                    'SERVICENOW_INSTANCE_URL': instance_url,
                    'SERVICENOW_CLIENT_ID': client_id,
                    'SERVICENOW_CLIENT_SECRET': client_secret,
                    'SERVICENOW_USERNAME': username,
                    'SERVICENOW_PASSWORD': password
                }.items() if not val
            ]
        })
        raise ValueError("Missing ServiceNow credentials in environment variables")
    
    return ServiceNowClient(
        instance_url=instance_url,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password
    )


def search_by_manufacturer(client: ServiceNowClient, manufacturer: str, 
                          fetch_details: bool, limit: int, max_hosts_per_version: int = 25) -> Dict:
    """Search for software packages by manufacturer with enhanced logging."""
    
    function_logger.log_debug(f"Starting manufacturer search for: {manufacturer}")
    
    results = {
        'status': 'success',
        'search_type': 'manufacturer',
        'manufacturer': manufacturer,
        'manufacturer_id': '',
        'total_packages': 0,
        'total_installations': 0,
        'software_products': {},
        'top_products': []
    }
    
    # First, try to get the company sys_id
    company_start_time = time.time()
    company_sys_id = client.get_company_sys_id(manufacturer)
    company_duration = time.time() - company_start_time
    
    if company_sys_id:
        results['manufacturer_id'] = company_sys_id
        function_logger.log_business_event('MANUFACTURER_COMPANY_FOUND', {
            'manufacturer': manufacturer,
            'company_sys_id': company_sys_id,
            'lookup_duration_ms': round(company_duration * 1000, 2)
        })
    else:
        function_logger.log_warning(f"Could not find company '{manufacturer}' in core_company table, using text search", {
            'manufacturer': manufacturer,
            'lookup_duration_ms': round(company_duration * 1000, 2)
        })
    
    # Build queries - only search manufacturer field
    queries = []
    
    if company_sys_id:
        # Use the sys_id for exact matching on manufacturer field only
        queries.append((f'manufacturer={company_sys_id}', True))
    else:
        # Fallback to LIKE query on manufacturer field if no company found
        queries.append((f'manufacturerLIKE{manufacturer}', False))
    
    all_packages = []
    seen_sys_ids = set()
    
    query_count = 0
    
    for query, is_exact in queries:
        query_count += 1
        function_logger.log_debug(f"Executing manufacturer query {query_count}: {query[:50]}...")
        
        params = {
            'sysparm_query': query,
            'sysparm_limit': str(limit),
            'sysparm_fields': 'sys_id,name,version,manufacturer,vendor,publisher,install_count,short_description'
        }
        
        query_start_time = time.time()
        response = client.api_request('/api/now/table/cmdb_ci_spkg', params)
        query_duration = time.time() - query_start_time
        
        if response and response.get('result'):
            packages_found = len(response['result'])
            
            function_logger.log_business_event('MANUFACTURER_QUERY_COMPLETE', {
                'query_number': query_count,
                'query_type': 'exact' if is_exact else 'like',
                'packages_found': packages_found,
                'query_duration_ms': round(query_duration * 1000, 2),
                'is_exact_match': is_exact
            })
            
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
                            manufacturer_name = client.get_company_name(pkg_manufacturer_id)
                            if manufacturer_name and manufacturer.lower() in manufacturer_name.lower():
                                seen_sys_ids.add(package['sys_id'])
                                all_packages.append(package)
        else:
            function_logger.log_warning(f"No packages found for manufacturer query {query_count}", {
                'query': query[:50],
                'query_duration_ms': round(query_duration * 1000, 2)
            })
    
    results['total_packages'] = len(all_packages)
    
    function_logger.log_business_event('MANUFACTURER_PACKAGES_COLLECTED', {
        'manufacturer': manufacturer,
        'total_packages': len(all_packages),
        'queries_executed': query_count
    })
    
    # Group by software product
    software_groups = defaultdict(lambda: {
        'versions': {},
        'total_installations': 0,
        'manufacturer': '',
        'manufacturer_id': ''
    })
    
    for package in all_packages:
        name = package.get('name', 'Unknown')
        version = package.get('version', 'Unknown')
        
        # Handle comma-formatted numbers in install_count
        install_count_str = str(package.get('install_count', 0))
        install_count = int(install_count_str.replace(',', '')) if install_count_str else 0
        
        # Get manufacturer ID and resolve to name
        manufacturer_field = package.get('manufacturer') or package.get('vendor') or package.get('publisher') or ''
        
        # Extract ID if it's a reference object
        if isinstance(manufacturer_field, dict):
            manufacturer_id = manufacturer_field.get('value', '')
        else:
            manufacturer_id = manufacturer_field
        
        manufacturer_name = client.get_company_name(manufacturer_id) if manufacturer_id else 'Unknown'
        
        software_groups[name]['versions'][version] = {
            'install_count': install_count,
            'sys_id': package['sys_id']
        }
        software_groups[name]['total_installations'] += install_count
        software_groups[name]['manufacturer'] = manufacturer_name
        software_groups[name]['manufacturer_id'] = manufacturer_id
        
        results['total_installations'] += install_count
    
    # Convert to response format
    for software_name, data in software_groups.items():
        results['software_products'][software_name] = {
            'manufacturer': data['manufacturer'],
            'manufacturer_id': data['manufacturer_id'],
            'total_installations': data['total_installations'],
            'version_count': len(data['versions']),
            'versions': [
                {
                    'version': ver,
                    'install_count': info['install_count']
                }
                for ver, info in sorted(data['versions'].items(), 
                                       key=lambda x: x[1]['install_count'], 
                                       reverse=True)[:10]
            ]
        }
    
    # Get top products
    results['top_products'] = sorted(
        [
            {
                'name': name,
                'total_installations': data['total_installations'],
                'version_count': len(data['versions'])
            }
            for name, data in software_groups.items()
        ],
        key=lambda x: x['total_installations'],
        reverse=True
    )[:20]
    
    function_logger.log_business_event('MANUFACTURER_SEARCH_SUMMARY', {
        'manufacturer': manufacturer,
        'software_products_count': len(results['software_products']),
        'top_products_count': len(results['top_products']),
        'total_installations': results['total_installations']
    })
    
    # Add sample installation details if requested
    if fetch_details and results['total_packages'] > 0 and len(all_packages) > 0:
        function_logger.log_debug("Fetching installation details for top package")
        details_start_time = time.time()
        
        # Get details for top package (limit to max_hosts_per_version)
        top_package = max(all_packages, key=lambda x: int(str(x.get('install_count', 0)).replace(',', '')))
        installations = get_installation_details(client, top_package['sys_id'], min(10, max_hosts_per_version))
        
        details_duration = time.time() - details_start_time
        
        if installations:
            install_count = int(str(top_package.get('install_count', 0)).replace(',', ''))
            results['sample_installations'] = {
                'software': top_package.get('name', 'Unknown'),
                'version': top_package.get('version', 'Unknown'),
                'total_installations': install_count,
                'hosts_fetched': len(installations),
                'is_sample': install_count > len(installations),
                'hosts': installations
            }
            
            function_logger.log_business_event('INSTALLATION_DETAILS_FETCHED', {
                'software': top_package.get('name', 'Unknown'),
                'version': top_package.get('version', 'Unknown'),
                'hosts_fetched': len(installations),
                'details_duration_ms': round(details_duration * 1000, 2)
            })
    
    return results


def search_by_software(client: ServiceNowClient, software_name: str, 
                       fetch_details: bool, limit: int, max_hosts_per_version: int = 25) -> Dict:
    """Search for specific software by name with enhanced logging."""
    
    function_logger.log_debug(f"Starting software search for: {software_name}")
    
    results = {
        'status': 'success',
        'search_type': 'software',
        'software_name': software_name,
        'total_versions': 0,
        'total_installations': 0,
        'versions': {},
        'installation_summary': {}
    }
    
    # Search for software by name
    params = {
        'sysparm_query': f'nameLIKE{software_name}',
        'sysparm_limit': str(limit),
        'sysparm_fields': 'sys_id,name,version,manufacturer,vendor,publisher,install_count,short_description'
    }
    
    function_logger.log_debug(f"Executing software search query: nameLIKE{software_name}")
    
    search_start_time = time.time()
    response = client.api_request('/api/now/table/cmdb_ci_spkg', params)
    search_duration = time.time() - search_start_time
    
    if not response or not response.get('result'):
        function_logger.log_warning(f"Software '{software_name}' not found in environment", {
            'software_name': software_name,
            'search_duration_ms': round(search_duration * 1000, 2)
        })
        results['status'] = 'not_found'
        results['message'] = f"Software '{software_name}' not found in environment"
        return results
    
    packages = response['result']
    results['total_versions'] = len(packages)
    
    function_logger.log_business_event('SOFTWARE_SEARCH_COMPLETE', {
        'software_name': software_name,
        'versions_found': len(packages),
        'search_duration_ms': round(search_duration * 1000, 2)
    })
    
    # Process each version
    version_count = 0
    for package in packages:
        version_count += 1
        version = package.get('version', 'Unknown')
        
        function_logger.log_debug(f"Processing software version {version_count}/{len(packages)}: {version}")
        
        # Handle comma-formatted numbers in install_count
        install_count_str = str(package.get('install_count', 0))
        install_count = int(install_count_str.replace(',', '')) if install_count_str else 0
        
        # Get manufacturer ID and name
        manufacturer_field = package.get('manufacturer') or package.get('vendor') or package.get('publisher') or ''
        
        # Extract ID if it's a reference object
        if isinstance(manufacturer_field, dict):
            manufacturer_id = manufacturer_field.get('value', '')
        else:
            manufacturer_id = manufacturer_field
            
        manufacturer_name = client.get_company_name(manufacturer_id) if manufacturer_id else 'Unknown'
        
        results['versions'][version] = {
            'full_name': package.get('name', software_name),
            'manufacturer': manufacturer_name,
            'manufacturer_id': manufacturer_id,
            'install_count': install_count,
            'sys_id': package['sys_id']
        }
        
        results['total_installations'] += install_count
        
        # Get installation details if requested (limit to max_hosts_per_version)
        if fetch_details and install_count > 0:
            function_logger.log_debug(f"Fetching installation details for version: {version}")
            details_start_time = time.time()
            
            # Limit the number of hosts we fetch for performance
            installations = get_installation_details(client, package['sys_id'], max_hosts_per_version)
            details_duration = time.time() - details_start_time
            
            if installations:
                results['versions'][version]['sample_hosts'] = installations
                # Add metadata about sampling
                results['versions'][version]['hosts_fetched'] = len(installations)
                results['versions'][version]['is_sample'] = install_count > len(installations)
                
                function_logger.log_business_event('VERSION_INSTALLATION_DETAILS_FETCHED', {
                    'software_name': software_name,
                    'version': version,
                    'install_count': install_count,
                    'hosts_fetched': len(installations),
                    'is_sample': install_count > len(installations),
                    'details_duration_ms': round(details_duration * 1000, 2)
                })
    
    # Create installation summary
    results['installation_summary'] = {
        'total_versions': results['total_versions'],
        'total_installations': results['total_installations'],
        'version_distribution': [
            {
                'version': ver,
                'install_count': data['install_count'],
                'manufacturer': data['manufacturer'],
                'manufacturer_id': data['manufacturer_id'],
                'sample_hosts_count': len(data.get('sample_hosts', [])),
                'is_sample': data['install_count'] > len(data.get('sample_hosts', []))
            }
            for ver, data in sorted(results['versions'].items(), 
                                   key=lambda x: x[1]['install_count'], 
                                   reverse=True)
        ]
    }
    
    function_logger.log_business_event('SOFTWARE_SEARCH_SUMMARY', {
        'software_name': software_name,
        'total_versions': results['total_versions'],
        'total_installations': results['total_installations'],
        'versions_with_details': len([v for v in results['versions'].values() if 'sample_hosts' in v])
    })
    
    return results


def get_installation_details(client: ServiceNowClient, software_sys_id: str, 
                            limit: int = 25) -> List[Dict]:
    """Get installation details for a software package with enhanced logging."""
    function_logger.log_debug(f"Getting installation details for software sys_id: {software_sys_id}")
    
    installations = []
    
    # First try cmdb_sam_sw_install table if we haven't been denied access yet
    if not client.sam_access_denied:
        function_logger.log_debug("Trying cmdb_sam_sw_install table for installation details")
        
        params = {
            'sysparm_query': f'software={software_sys_id}',
            'sysparm_limit': str(limit),
            'sysparm_fields': 'sys_id,installed_on,install_date,install_status,version'
        }
        
        sam_start_time = time.time()
        response = client.api_request('/api/now/table/cmdb_sam_sw_install', params)
        sam_duration = time.time() - sam_start_time
        
        if response and response.get('result'):
            sam_records = len(response['result'])
            
            function_logger.log_business_event('SAM_INSTALLATION_RECORDS_FOUND', {
                'software_sys_id': software_sys_id,
                'sam_records_count': sam_records,
                'sam_query_duration_ms': round(sam_duration * 1000, 2)
            })
            
            for install in response['result']:
                host_ref = install.get('installed_on', {})
                
                if isinstance(host_ref, dict) and host_ref.get('value'):
                    host_sys_id = host_ref['value']
                    host_start_time = time.time()
                    host_response = client.api_request(f'/api/now/table/cmdb_ci/{host_sys_id}')
                    host_duration = time.time() - host_start_time
                    
                    if host_response and host_response.get('result'):
                        host = host_response['result']
                        installations.append({
                            'host_name': host.get('name', 'Unknown'),
                            'host_ip': host.get('ip_address', 'N/A'),
                            'host_os': host.get('os', host.get('operating_system', 'Unknown')),
                            'install_date': install.get('install_date', 'Unknown'),
                            'install_status': install.get('install_status', 'Unknown'),
                            'version': install.get('version', 'Unknown')
                        })
                        
                        if len(installations) % 5 == 0:
                            function_logger.log_debug(f"Processed {len(installations)} installations so far...")
        else:
            function_logger.log_debug("No SAM installation records found", {
                'software_sys_id': software_sys_id,
                'sam_query_duration_ms': round(sam_duration * 1000, 2)
            })
    
    # If no results from SAM table (either no access or no data), try relationships
    if not installations:
        function_logger.log_debug("Trying cmdb_rel_ci table for installation relationships")
        
        params = {
            'sysparm_query': f'child={software_sys_id}^type.name=Installed on::Installs',
            'sysparm_limit': str(limit),
            'sysparm_fields': 'parent'
        }
        
        rel_start_time = time.time()
        response = client.api_request('/api/now/table/cmdb_rel_ci', params)
        rel_duration = time.time() - rel_start_time
        
        if response and response.get('result'):
            rel_records = len(response['result'])
            
            function_logger.log_business_event('RELATIONSHIP_INSTALLATION_RECORDS_FOUND', {
                'software_sys_id': software_sys_id,
                'relationship_records_count': rel_records,
                'relationship_query_duration_ms': round(rel_duration * 1000, 2)
            })
            
            for rel in response['result']:
                parent_ref = rel.get('parent', {})
                
                if isinstance(parent_ref, dict) and parent_ref.get('value'):
                    host_sys_id = parent_ref['value']
                    host_response = client.api_request(f'/api/now/table/cmdb_ci/{host_sys_id}')
                    
                    if host_response and host_response.get('result'):
                        host = host_response['result']
                        installations.append({
                            'host_name': host.get('name', 'Unknown'),
                            'host_ip': host.get('ip_address', 'N/A'),
                            'host_os': host.get('os', host.get('operating_system', 'Unknown')),
                            'install_date': 'Unknown',
                            'install_status': 'Active'
                        })
                        
                        if len(installations) % 5 == 0:
                            function_logger.log_debug(f"Processed {len(installations)} relationship installations so far...")
        else:
            function_logger.log_warning("No installation relationships found", {
                'software_sys_id': software_sys_id,
                'relationship_query_duration_ms': round(rel_duration * 1000, 2)
            })
    
    function_logger.log_business_event('INSTALLATION_DETAILS_COMPLETE', {
        'software_sys_id': software_sys_id,
        'installations_found': len(installations),
        'data_source': 'sam' if not client.sam_access_denied and installations else 'relationships'
    })
    
    return installations