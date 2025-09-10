"""
Azure Function: Software Inventory
HTTP triggered function to query software inventory from cmdb_ci_spkg
"""

import azure.functions as func
import json
import logging
import os
from typing import Dict, Any, List, Optional
from collections import defaultdict

from services import ServiceNowClient

logger = logging.getLogger(__name__)


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
        "max_hosts_per_version": 25             # optional, default 25, max hosts to fetch per version
    }
    """
    logger.info('Software Inventory function triggered')
    
    try:
        # Validate API key
        api_key = req.headers.get('X-API-Key')
        expected_key = os.environ.get('API_KEY')
        
        if expected_key and api_key != expected_key:
            return func.HttpResponse(
                json.dumps({"error": "Invalid API key"}),
                status_code=401,
                mimetype="application/json"
            )
        
        # Parse request body
        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid JSON in request body"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Validate parameters
        search_type = req_body.get('search_type')
        if search_type not in ['manufacturer', 'software']:
            return func.HttpResponse(
                json.dumps({"error": "search_type must be 'manufacturer' or 'software'"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Get search parameters
        manufacturer = req_body.get('manufacturer')
        software_name = req_body.get('software_name')
        fetch_details = req_body.get('fetch_details', True)
        limit = min(req_body.get('limit', 1000), 1000)  # Cap at 1000
        max_hosts_per_version = min(req_body.get('max_hosts_per_version', 25), 100)  # Default 25, max 100
        
        # Validate search criteria
        if search_type == 'manufacturer' and not manufacturer:
            return func.HttpResponse(
                json.dumps({"error": "manufacturer is required when search_type is 'manufacturer'"}),
                status_code=400,
                mimetype="application/json"
            )
        
        if search_type == 'software' and not software_name:
            return func.HttpResponse(
                json.dumps({"error": "software_name is required when search_type is 'software'"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Initialize ServiceNow client
        client = create_servicenow_client()
        
        # Perform search
        if search_type == 'manufacturer':
            results = search_by_manufacturer(client, manufacturer, fetch_details, limit, max_hosts_per_version)
        else:
            results = search_by_software(client, software_name, fetch_details, limit, max_hosts_per_version)
        
        # Add metadata about the query
        results['metadata'] = {
            'fetch_details': fetch_details,
            'max_hosts_per_version': max_hosts_per_version if fetch_details else 0,
            'note': 'Host details are limited to improve performance. Use max_hosts_per_version parameter to adjust (max 100).'
        }
        
        # Add permission warnings if any
        if client.permission_warnings:
            results['permission_warnings'] = list(client.permission_warnings)
        
        return func.HttpResponse(
            json.dumps(results, default=str),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def create_servicenow_client() -> ServiceNowClient:
    """Create ServiceNow client with credentials from environment."""
    instance_url = os.environ.get('SERVICENOW_INSTANCE_URL')
    client_id = os.environ.get('SERVICENOW_CLIENT_ID')
    client_secret = os.environ.get('SERVICENOW_CLIENT_SECRET')
    username = os.environ.get('SERVICENOW_USERNAME')
    password = os.environ.get('SERVICENOW_PASSWORD')
    
    if not all([instance_url, client_id, client_secret, username, password]):
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
    """Search for software packages by manufacturer."""
    
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
    company_sys_id = client.get_company_sys_id(manufacturer)
    
    if company_sys_id:
        results['manufacturer_id'] = company_sys_id
        logger.info(f"Found company '{manufacturer}' with sys_id: {company_sys_id}")
    else:
        logger.warning(f"Could not find company '{manufacturer}' in core_company table, using text search")
    
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
    
    for query, is_exact in queries:
        params = {
            'sysparm_query': query,
            'sysparm_limit': str(limit),
            'sysparm_fields': 'sys_id,name,version,manufacturer,vendor,publisher,install_count,short_description'
        }
        
        response = client.api_request('/api/now/table/cmdb_ci_spkg', params)
        
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
                            manufacturer_name = client.get_company_name(pkg_manufacturer_id)
                            if manufacturer_name and manufacturer.lower() in manufacturer_name.lower():
                                seen_sys_ids.add(package['sys_id'])
                                all_packages.append(package)
    
    results['total_packages'] = len(all_packages)
    
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
    
    # Add sample installation details if requested
    if fetch_details and results['total_packages'] > 0 and len(all_packages) > 0:
        # Get details for top package (limit to max_hosts_per_version)
        top_package = max(all_packages, key=lambda x: int(str(x.get('install_count', 0)).replace(',', '')))
        installations = get_installation_details(client, top_package['sys_id'], min(10, max_hosts_per_version))
        
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
    
    return results


def search_by_software(client: ServiceNowClient, software_name: str, 
                       fetch_details: bool, limit: int, max_hosts_per_version: int = 25) -> Dict:
    """Search for specific software by name."""
    
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
    
    response = client.api_request('/api/now/table/cmdb_ci_spkg', params)
    
    if not response or not response.get('result'):
        results['status'] = 'not_found'
        results['message'] = f"Software '{software_name}' not found in environment"
        return results
    
    packages = response['result']
    results['total_versions'] = len(packages)
    
    # Process each version
    for package in packages:
        version = package.get('version', 'Unknown')
        
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
            # Limit the number of hosts we fetch for performance
            installations = get_installation_details(client, package['sys_id'], max_hosts_per_version)
            if installations:
                results['versions'][version]['sample_hosts'] = installations
                # Add metadata about sampling
                results['versions'][version]['hosts_fetched'] = len(installations)
                results['versions'][version]['is_sample'] = install_count > len(installations)
    
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
    
    return results


def get_installation_details(client: ServiceNowClient, software_sys_id: str, 
                            limit: int = 25) -> List[Dict]:
    """Get installation details for a software package."""
    installations = []
    
    # First try cmdb_sam_sw_install table if we haven't been denied access yet
    if not client.sam_access_denied:
        params = {
            'sysparm_query': f'software={software_sys_id}',
            'sysparm_limit': str(limit),
            'sysparm_fields': 'sys_id,installed_on,install_date,install_status,version'
        }
        
        response = client.api_request('/api/now/table/cmdb_sam_sw_install', params)
        
        if response and response.get('result'):
            for install in response['result']:
                host_ref = install.get('installed_on', {})
                
                if isinstance(host_ref, dict) and host_ref.get('value'):
                    host_sys_id = host_ref['value']
                    host_response = client.api_request(f'/api/now/table/cmdb_ci/{host_sys_id}')
                    
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
    
    # If no results from SAM table (either no access or no data), try relationships
    if not installations:
        params = {
            'sysparm_query': f'child={software_sys_id}^type.name=Installed on::Installs',
            'sysparm_limit': str(limit),
            'sysparm_fields': 'parent'
        }
        
        response = client.api_request('/api/now/table/cmdb_rel_ci', params)
        
        if response and response.get('result'):
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
    
    return installations