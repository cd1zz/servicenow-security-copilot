"""
Azure Function: Batch Analyze
HTTP triggered function to analyze multiple vulnerabilities in batch
Enhanced with comprehensive logging for debugging
"""

import azure.functions as func
import json
import logging
import os
import time
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from services import ServiceNowClient, VulnerabilityAnalyzer
from services.logging_utils import FunctionLogger

# Configure logger for this function
function_logger = FunctionLogger(__name__)


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
    # Start request logging
    function_logger.start_request(req, {
        'function_name': 'batch-analyze',
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
        vuln_ids = req_body.get('vuln_ids')
        if not vuln_ids or not isinstance(vuln_ids, list):
            function_logger.log_warning("Missing or invalid vuln_ids parameter", {
                'vuln_ids_type': type(vuln_ids).__name__ if vuln_ids else 'None',
                'vuln_ids_length': len(vuln_ids) if isinstance(vuln_ids, list) else 0
            })
            response = func.HttpResponse(
                json.dumps({"error": "Missing or invalid parameter: vuln_ids (must be a list)"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'invalid_vuln_ids'})
            return response
        
        # Limit batch size
        max_batch_size = 50
        if len(vuln_ids) > max_batch_size:
            function_logger.log_warning(f"Batch size exceeds maximum", {
                'requested_size': len(vuln_ids),
                'max_size': max_batch_size
            })
            response = func.HttpResponse(
                json.dumps({"error": f"Batch size exceeds maximum of {max_batch_size}"}),
                status_code=400,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'validation_error': 'batch_size_exceeded'})
            return response
        
        # Get optional parameters
        fetch_all_details = req_body.get('fetch_all_details', False)
        include_patched = req_body.get('include_patched', False)
        confirmation_state = req_body.get('confirmation_state')
        use_parallel = req_body.get('parallel', True)
        
        function_logger.log_business_event('BATCH_ANALYSIS_PARAMETERS', {
            'batch_size': len(vuln_ids),
            'vuln_ids': vuln_ids,
            'fetch_all_details': fetch_all_details,
            'include_patched': include_patched,
            'confirmation_state': confirmation_state,
            'use_parallel': use_parallel,
            'vuln_types': [('QID' if vid.upper().startswith('QID-') or vid.isdigit() else 'CVE') for vid in vuln_ids]
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
        
        # Process vulnerabilities
        function_logger.log_business_event('BATCH_PROCESSING_START', {
            'processing_mode': 'parallel' if use_parallel and len(vuln_ids) > 1 else 'sequential',
            'vulnerability_count': len(vuln_ids)
        })
        
        processing_start_time = time.time()
        
        try:
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
                
            processing_duration = time.time() - processing_start_time
            
            function_logger.log_business_event('BATCH_PROCESSING_COMPLETE', {
                'processing_duration_ms': round(processing_duration * 1000, 2),
                'results_count': len(results),
                'successful_analyses': len([r for r in results if r.get('found', False)]),
                'failed_analyses': len([r for r in results if 'error' in r]),
                'not_found_analyses': len([r for r in results if not r.get('found', False) and 'error' not in r])
            })
            
        except Exception as e:
            processing_duration = time.time() - processing_start_time
            function_logger.log_error(e, {
                'processing_stage': 'batch_analysis',
                'duration_ms': round(processing_duration * 1000, 2)
            })
            response = func.HttpResponse(
                json.dumps({"error": f"Batch processing failed: {str(e)}"}),
                status_code=500,
                mimetype="application/json"
            )
            function_logger.end_request(response, {'processing_error': True})
            return response
        
        # Format response
        function_logger.log_debug("Formatting batch response")
        format_start_time = time.time()
        
        try:
            response_data = format_batch_response(results)
            format_duration = time.time() - format_start_time
            
            function_logger.log_business_event('BATCH_RESPONSE_FORMATTING_COMPLETE', {
                'format_duration_ms': round(format_duration * 1000, 2),
                'response_size': len(json.dumps(response_data)),
                'summary': response_data.get('summary', {})
            })
            
        except Exception as e:
            format_duration = time.time() - format_start_time
            function_logger.log_error(e, {
                'formatting_stage': 'batch_response_formatting',
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
            'batch_size': len(vuln_ids),
            'processing_summary': response_data.get('summary', {})
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


def analyze_sequential(analyzer: VulnerabilityAnalyzer, vuln_ids: List[str],
                      fetch_all_details: bool, include_patched: bool,
                      confirmation_state: str) -> List[Dict[str, Any]]:
    """Analyze vulnerabilities sequentially with detailed logging."""
    function_logger.log_business_event('SEQUENTIAL_ANALYSIS_START', {
        'vulnerability_count': len(vuln_ids)
    })
    
    results = []
    for i, vuln_id in enumerate(vuln_ids, 1):
        function_logger.log_debug(f"Analyzing vulnerability {i}/{len(vuln_ids)}: {vuln_id}")
        analysis_start_time = time.time()
        
        try:
            result = analyzer.analyze_vulnerability(
                vuln_id=vuln_id,
                fetch_all_details=fetch_all_details,
                include_patched=include_patched,
                confirmation_state=confirmation_state
            )
            
            analysis_duration = time.time() - analysis_start_time
            
            function_logger.log_business_event('SEQUENTIAL_ANALYSIS_ITEM_COMPLETE', {
                'vuln_id': vuln_id,
                'item_number': i,
                'total_items': len(vuln_ids),
                'duration_ms': round(analysis_duration * 1000, 2),
                'found': result.get('found', False),
                'systems_count': len(result.get('systems', []))
            })
            
            results.append(result)
            
        except Exception as e:
            analysis_duration = time.time() - analysis_start_time
            
            function_logger.log_error(e, {
                'vuln_id': vuln_id,
                'item_number': i,
                'total_items': len(vuln_ids),
                'duration_ms': round(analysis_duration * 1000, 2),
                'analysis_type': 'sequential'
            })
            
            results.append({
                "vuln_id": vuln_id,
                "error": str(e),
                "found": False
            })
    
    function_logger.log_business_event('SEQUENTIAL_ANALYSIS_COMPLETE', {
        'total_processed': len(results),
        'successful_count': len([r for r in results if 'error' not in r])
    })
    
    return results


def analyze_parallel(analyzer: VulnerabilityAnalyzer, vuln_ids: List[str],
                    fetch_all_details: bool, include_patched: bool,
                    confirmation_state: str) -> List[Dict[str, Any]]:
    """Analyze vulnerabilities in parallel with detailed logging."""
    max_workers = min(5, len(vuln_ids))  # Limit concurrent connections
    
    function_logger.log_business_event('PARALLEL_ANALYSIS_START', {
        'vulnerability_count': len(vuln_ids),
        'max_workers': max_workers,
        'worker_strategy': 'ThreadPoolExecutor'
    })
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_vuln = {}
        submission_start_time = time.time()
        
        for vuln_id in vuln_ids:
            future = executor.submit(
                analyzer.analyze_vulnerability,
                vuln_id=vuln_id,
                fetch_all_details=fetch_all_details,
                include_patched=include_patched,
                confirmation_state=confirmation_state
            )
            future_to_vuln[future] = vuln_id
        
        submission_duration = time.time() - submission_start_time
        
        function_logger.log_business_event('PARALLEL_TASKS_SUBMITTED', {
            'tasks_submitted': len(future_to_vuln),
            'submission_duration_ms': round(submission_duration * 1000, 2)
        })
        
        # Collect results as they complete
        completed_count = 0
        collection_start_time = time.time()
        
        for future in as_completed(future_to_vuln):
            completed_count += 1
            vuln_id = future_to_vuln[future]
            result_start_time = time.time()
            
            try:
                result = future.result(timeout=30)  # 30 second timeout per vuln
                result_duration = time.time() - result_start_time
                
                function_logger.log_business_event('PARALLEL_TASK_COMPLETE', {
                    'vuln_id': vuln_id,
                    'completed_count': completed_count,
                    'total_tasks': len(future_to_vuln),
                    'result_duration_ms': round(result_duration * 1000, 2),
                    'found': result.get('found', False),
                    'systems_count': len(result.get('systems', []))
                })
                
                results.append(result)
                
            except Exception as e:
                result_duration = time.time() - result_start_time
                
                function_logger.log_error(e, {
                    'vuln_id': vuln_id,
                    'completed_count': completed_count,
                    'total_tasks': len(future_to_vuln),
                    'result_duration_ms': round(result_duration * 1000, 2),
                    'analysis_type': 'parallel',
                    'timeout_used': 30
                })
                
                results.append({
                    "vuln_id": vuln_id,
                    "error": str(e),
                    "found": False
                })
        
        collection_duration = time.time() - collection_start_time
        
        function_logger.log_business_event('PARALLEL_ANALYSIS_COMPLETE', {
            'total_processed': len(results),
            'collection_duration_ms': round(collection_duration * 1000, 2),
            'successful_count': len([r for r in results if 'error' not in r]),
            'failed_count': len([r for r in results if 'error' in r])
        })
    
    return results


def format_batch_response(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format batch analysis results for API response with logging."""
    function_logger.log_debug("Formatting batch response", {
        'results_count': len(results)
    })
    
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
    
    function_logger.log_business_event('BATCH_RESPONSE_SUMMARY', {
        'total_processed': response["total_processed"],
        'found': response["summary"]["found"],
        'not_found': response["summary"]["not_found"],
        'errors': response["summary"]["errors"],
        'total_vulnerable_systems': response["summary"]["total_vulnerable_systems"],
        'success_rate': round((response["summary"]["found"] / response["total_processed"]) * 100, 2) if response["total_processed"] > 0 else 0
    })
    
    return response