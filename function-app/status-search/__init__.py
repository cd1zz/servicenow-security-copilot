"""
Azure Function: Status Search
HTTP triggered function to search vulnerabilities by confirmation status
"""

import azure.functions as func
import json
import logging
import os
from typing import Dict, Any

from services import ServiceNowClient, VulnerabilityAnalyzer

logger = logging.getLogger(__name__)


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
    logger.info('Status Search function triggered')
    
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
        
        # Validate required parameters
        confirmation_state = req_body.get('confirmation_state')
        if not confirmation_state:
            return func.HttpResponse(
                json.dumps({"error": "Missing required parameter: confirmation_state"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Validate confirmation state value
        valid_states = ['confirmed', 'potential', 'potential-investigation', 
                       'potential-patch', 'potential-low', 'none']
        if confirmation_state not in valid_states:
            return func.HttpResponse(
                json.dumps({
                    "error": f"Invalid confirmation_state. Must be one of: {', '.join(valid_states)}"
                }),
                status_code=400,
                mimetype="application/json"
            )
        
        # Get optional parameters
        days = req_body.get('days', 14)
        fetch_all_details = req_body.get('fetch_all_details', False)
        
        # Initialize ServiceNow client
        client = create_servicenow_client()
        analyzer = VulnerabilityAnalyzer(client)
        
        # Search by confirmation status
        results = analyzer.search_by_confirmation_status(
            confirmation_state=confirmation_state,
            days=days,
            fetch_all_details=fetch_all_details
        )
        
        # Format response
        response = format_status_search_response(results)
        
        return func.HttpResponse(
            json.dumps(response, default=str),
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
    """Create ServiceNow client with credentials from environment/Key Vault."""
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


def format_status_search_response(results: Dict[str, Any]) -> Dict[str, Any]:
    """Format the status search results for API response."""
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
        
        response['top_vulnerabilities'] = [
            {
                "id": vuln['id'],
                "summary": vuln['summary'][:200],  # Truncate long summaries
                "cvss_score": vuln['cvss_score'],
                "affected_systems": vuln['affected_systems'],
                "source": vuln.get('source', 'Unknown'),
                "cve_ids": vuln.get('cve_ids', [])[:5]  # Limit CVEs
            }
            for vuln in sorted_vulns[:20]  # Top 20 vulnerabilities
        ]
    
    # Add top affected systems
    if results.get('systems'):
        sorted_systems = sorted(
            results['systems'],
            key=lambda x: x.get('risk_score', 0),
            reverse=True
        )
        
        response['top_systems'] = [
            {
                "dns": system['dns'],
                "vi_number": system.get('vi_number', 'N/A'),
                "ip_address": system['ip_address'],
                "risk_score": system['risk_score'],
                "assignment_group": system.get('assignment_group', 'N/A'),
                "first_found": system['first_found'],
                "description": system.get('description', '')
            }
            for system in sorted_systems[:20]  # Top 20 systems
        ]
    
    return response