"""
Azure Function: Batch Analyze
HTTP triggered function to analyze multiple vulnerabilities in batch
"""

import azure.functions as func
import json
import logging
import os
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from services import ServiceNowClient, VulnerabilityAnalyzer

logger = logging.getLogger(__name__)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP trigger function to analyze multiple vulnerabilities.
    
    Expected JSON body:
    {
        "vuln_ids": ["CVE-2024-1234", "QID-123456", "CVE-2024-5678"],  # required
        "fetch_all_details": false,  # optional, default false
        "include_patched": false,     # optional, default false
        "confirmation_state": "confirmed",  # optional
        "parallel": true              # optional, default true
    }
    """
    logger.info('Batch Analyze function triggered')
    
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
        vuln_ids = req_body.get('vuln_ids')
        if not vuln_ids or not isinstance(vuln_ids, list):
            return func.HttpResponse(
                json.dumps({"error": "Missing or invalid parameter: vuln_ids (must be a list)"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Limit batch size
        max_batch_size = 50
        if len(vuln_ids) > max_batch_size:
            return func.HttpResponse(
                json.dumps({"error": f"Batch size exceeds maximum of {max_batch_size}"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Get optional parameters
        fetch_all_details = req_body.get('fetch_all_details', False)
        include_patched = req_body.get('include_patched', False)
        confirmation_state = req_body.get('confirmation_state')
        use_parallel = req_body.get('parallel', True)
        
        # Initialize ServiceNow client
        client = create_servicenow_client()
        analyzer = VulnerabilityAnalyzer(client)
        
        # Process vulnerabilities
        if use_parallel and len(vuln_ids) > 1:
            results = analyze_parallel(
                analyzer, vuln_ids, fetch_all_details, 
                include_patched, confirmation_state
            )
        else:
            results = analyze_sequential(
                analyzer, vuln_ids, fetch_all_details, 
                include_patched, confirmation_state
            )
        
        # Format response
        response = format_batch_response(results)
        
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


def analyze_sequential(analyzer: VulnerabilityAnalyzer, vuln_ids: List[str],
                      fetch_all_details: bool, include_patched: bool,
                      confirmation_state: str) -> List[Dict[str, Any]]:
    """Analyze vulnerabilities sequentially."""
    results = []
    for vuln_id in vuln_ids:
        try:
            result = analyzer.analyze_vulnerability(
                vuln_id=vuln_id,
                fetch_all_details=fetch_all_details,
                include_patched=include_patched,
                confirmation_state=confirmation_state
            )
            results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing {vuln_id}: {str(e)}")
            results.append({
                "vuln_id": vuln_id,
                "error": str(e),
                "found": False
            })
    return results


def analyze_parallel(analyzer: VulnerabilityAnalyzer, vuln_ids: List[str],
                    fetch_all_details: bool, include_patched: bool,
                    confirmation_state: str) -> List[Dict[str, Any]]:
    """Analyze vulnerabilities in parallel."""
    results = []
    max_workers = min(5, len(vuln_ids))  # Limit concurrent connections
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_vuln = {
            executor.submit(
                analyzer.analyze_vulnerability,
                vuln_id=vuln_id,
                fetch_all_details=fetch_all_details,
                include_patched=include_patched,
                confirmation_state=confirmation_state
            ): vuln_id
            for vuln_id in vuln_ids
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_vuln):
            vuln_id = future_to_vuln[future]
            try:
                result = future.result(timeout=30)  # 30 second timeout per vuln
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {vuln_id}: {str(e)}")
                results.append({
                    "vuln_id": vuln_id,
                    "error": str(e),
                    "found": False
                })
    
    return results


def format_batch_response(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format batch analysis results for API response."""
    response = {
        "status": "success",
        "total_processed": len(results),
        "summary": {
            "found": 0,
            "not_found": 0,
            "errors": 0,
            "total_vulnerable_systems": 0
        },
        "results": []
    }
    
    for result in results:
        if "error" in result:
            response["summary"]["errors"] += 1
            response["results"].append({
                "vuln_id": result.get("vuln_id"),
                "status": "error",
                "error": result.get("error")
            })
        elif not result.get("found"):
            response["summary"]["not_found"] += 1
            response["results"].append({
                "vuln_id": result.get("vuln_id"),
                "status": "not_found"
            })
        else:
            response["summary"]["found"] += 1
            response["summary"]["total_vulnerable_systems"] += result.get("total_vulnerable_systems", 0)
            
            formatted_result = {
                "vuln_id": result.get("vuln_id"),
                "status": "found",
                "vuln_type": result.get("vuln_type"),
                "summary": result.get("summary"),
                "cvss_score": result.get("cvss_score"),
                "total_vulnerable_systems": result.get("total_vulnerable_systems", 0),
                "systems_retrieved": result.get("systems_retrieved", 0)
            }
            
            # Add filtered count if applicable
            if "filtered_vulnerable_systems" in result:
                formatted_result["filtered_vulnerable_systems"] = result["filtered_vulnerable_systems"]
            
            # Add associated CVEs for QIDs
            if result.get("associated_cves"):
                formatted_result["associated_cves"] = result["associated_cves"]
            
            # Add limited system details
            if result.get("systems"):
                formatted_result["systems_sample"] = [
                    {
                        "name": system["name"],
                        "ip_address": system["ip_address"]
                    }
                    for system in result["systems"][:5]  # Only first 5 systems
                ]
            
            response["results"].append(formatted_result)
    
    return response