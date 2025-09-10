"""
Azure Function: Status Search
HTTP triggered function to search vulnerabilities by confirmation status
Enhanced with comprehensive logging for debugging
"""

import azure.functions as func
import json
import logging
import os
import time
from typing import Dict, Any

from services import ServiceNowClient, VulnerabilityAnalyzer
from services.logging_utils import FunctionLogger

# Configure logger for this function
function_logger = FunctionLogger(__name__)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP trigger function to search vulnerabilities by confirmation status.
    
    Expected JSON body:
    {
        "confirmation_state": "confirmed",  # required: confirmed, potential, potential-investigation, etc.
        "days": 14,                        # optional, default 14
        "fetch_all_details": false         # optional, default false
    }
    """
    # Start request logging
    function_logger.start_request(req, {
        'function_name': 'status-search',
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
        
        # Validate required parameters
        confirmation_state = req_body.get('confirmation_state')
        if not confirmation_state:
            function_logger.log_warning("Missing confirmation_state parameter", {
                'provided_params': list(req_body.keys()) if req_body else []
            })
            response = func.HttpResponse(
                json.dumps({"error": "Missing required parameter: confirmation_state"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'missing_confirmation_state'})
            return response
        
        # Validate confirmation state value
        valid_states = ['confirmed', 'potential', 'potential-investigation', 
                       'potential-patch', 'potential-low', 'none']
        if confirmation_state not in valid_states:
            function_logger.log_warning("Invalid confirmation_state value", {
                'provided_state': confirmation_state,
                'valid_states': valid_states
            })
            response = func.HttpResponse(
                json.dumps({
                    "error": f"Invalid confirmation_state. Must be one of: {', '.join(valid_states)}"
                }),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'invalid_confirmation_state'})
            return response
        
        # Get optional parameters
        days = req_body.get('days', 14)
        fetch_all_details = req_body.get('fetch_all_details', False)
        
        function_logger.log_business_event('STATUS_SEARCH_PARAMETERS', {
            'confirmation_state': confirmation_state,
            'days': days,
            'fetch_all_details': fetch_all_details
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
        
        analyzer = VulnerabilityAnalyzer(client)
        
        # Search by confirmation status
        function_logger.log_business_event('STATUS_SEARCH_START', {
            'confirmation_state': confirmation_state,
            'days': days,
            'fetch_all_details': fetch_all_details
        })
        
        search_start_time = time.time()
        
        try:
            results = analyzer.search_by_confirmation_status(
                confirmation_state=confirmation_state,
                days=days,
                fetch_all_details=fetch_all_details
            )
            
            search_duration = time.time() - search_start_time
            
            function_logger.log_business_event('STATUS_SEARCH_COMPLETE', {
                'confirmation_state': confirmation_state,
                'search_duration_ms': round(search_duration * 1000, 2),
                'total_vulnerable_items': results.get('total_vulnerable_items', 0),
                'unique_vulnerabilities': results.get('unique_vulnerabilities', 0),
                'unique_systems': results.get('unique_systems', 0)
            })
            
        except Exception as e:
            search_duration = time.time() - search_start_time
            function_logger.log_error(e, {
                'search_stage': 'status_search',
                'confirmation_state': confirmation_state,
                'duration_ms': round(search_duration * 1000, 2)
            })
            response = func.HttpResponse(
                json.dumps({"error": f"Status search failed: {str(e)}"}),
                status_code=500,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'search_error': True})
            return response
        
        # Format response
        function_logger.log_debug("Formatting status search response")
        format_start_time = time.time()
        
        try:
            response_data = format_status_search_response(results)
            format_duration = time.time() - format_start_time
            
            function_logger.log_business_event('STATUS_SEARCH_RESPONSE_FORMATTING_COMPLETE', {
                'format_duration_ms': round(format_duration * 1000, 2),
                'response_size': len(json.dumps(response_data)),
                'statistics': response_data.get('statistics', {})
            })
            
        except Exception as e:
            format_duration = time.time() - format_start_time
            function_logger.log_error(e, {
                'formatting_stage': 'status_search_response_formatting',
                'duration_ms': round(format_duration * 1000, 2)
            })
            response = func.HttpResponse(
                json.dumps({"error": f"Response formatting failed: {str(e)}"}),
                status_code=500,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'formatting_error': True})
            return response
        
        # Create successful response
        response = func.HttpResponse(
            json.dumps(response_data, default=str),
            status_code=200,
            mimetype="application/json"
        )
        
        function_logger.end_request(response, {
            'confirmation_state': confirmation_state,
            'search_statistics': response_data.get('statistics', {})
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
    """Create ServiceNow client with credentials from environment/Key Vault."""
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


def format_status_search_response(results: Dict[str, Any]) -> Dict[str, Any]:
    """Format the status search results for API response."""
    function_logger.log_debug("Formatting status search response", {
        'results_keys': list(results.keys()),
        'vulnerabilities_count': len(results.get('vulnerabilities', [])),
        'systems_count': len(results.get('systems', []))
    })
    
    response = {
        "status": "success",
        "search_type": "confirmation_status",
        "confirmation_state": results.get('confirmation_state'),
        "days": results.get('days'),
        "timestamp": results.get('timestamp'),
        "statistics": {
            "unique_vulnerabilities": results.get('unique_vulnerabilities', 0),
            "unique_systems": results.get('unique_systems', 0),
            "total_vulnerable_items": results.get('total_vulnerable_items', 0)
        }
    }
    
    # Add top vulnerabilities
    if results.get('vulnerabilities'):
        sorted_vulns = sorted(
            results['vulnerabilities'], 
            key=lambda x: x['affected_systems'], 
            reverse=True
        )
        
        top_vulns = []
        for vuln in sorted_vulns[:20]:  # Top 20 vulnerabilities
            top_vulns.append({
                "id": vuln['id'],
                "summary": vuln['summary'][:200],  # Truncate long summaries
                "cvss_score": vuln['cvss_score'],
                "affected_systems": vuln['affected_systems'],
                "source": vuln.get('source', 'Unknown'),
                "cve_ids": vuln.get('cve_ids', [])[:5]  # Limit CVEs
            })
        
        response['top_vulnerabilities'] = top_vulns
        
        function_logger.log_business_event('TOP_VULNERABILITIES_FORMATTED', {
            'total_vulnerabilities': len(results['vulnerabilities']),
            'top_vulnerabilities_count': len(top_vulns),
            'max_affected_systems': max((v['affected_systems'] for v in sorted_vulns), default=0)
        })
    
    # Add top affected systems
    if results.get('systems'):
        sorted_systems = sorted(
            results['systems'],
            key=lambda x: x.get('risk_score', 0),
            reverse=True
        )
        
        top_systems = []
        for system in sorted_systems[:20]:  # Top 20 systems
            top_systems.append({
                "dns": system['dns'],
                "vi_number": system.get('vi_number', 'N/A'),
                "ip_address": system['ip_address'],
                "risk_score": system['risk_score'],
                "assignment_group": system.get('assignment_group', 'N/A'),
                "first_found": system['first_found'],
                "description": system.get('description', '')
            })
        
        response['top_systems'] = top_systems
        
        function_logger.log_business_event('TOP_SYSTEMS_FORMATTED', {
            'total_systems': len(results['systems']),
            'top_systems_count': len(top_systems),
            'max_risk_score': max((s.get('risk_score', 0) for s in sorted_systems), default=0)
        })
    
    function_logger.log_debug("Status search response formatting completed", {
        'response_status': response['status'],
        'statistics': response['statistics'],
        'has_vulnerabilities': 'top_vulnerabilities' in response,
        'has_systems': 'top_systems' in response
    })
    
    return response