"""
Enhanced logging utilities for Azure Functions
Provides structured logging, performance tracking, and error context
"""

import logging
import time
import json
import traceback
import uuid
from functools import wraps
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import azure.functions as func


class FunctionLogger:
    """Enhanced logger for Azure Functions with structured logging and performance tracking"""
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
        self.correlation_id = str(uuid.uuid4())
        self.request_start_time = None
        self.function_name = logger_name
        
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for request tracking"""
        self.correlation_id = correlation_id
        
    def start_request(self, req: func.HttpRequest, additional_context: Dict[str, Any] = None):
        """Log request start with detailed context"""
        self.request_start_time = time.time()
        
        # Extract correlation ID from headers if available
        if 'x-correlation-id' in req.headers:
            self.correlation_id = req.headers['x-correlation-id']
        elif 'x-ms-request-id' in req.headers:
            self.correlation_id = req.headers['x-ms-request-id']
            
        context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'method': req.method,
            'url': req.url,
            'headers': dict(req.headers),
            'query_params': dict(req.params),
            'content_length': len(req.get_body()) if req.get_body() else 0,
            'user_agent': req.headers.get('User-Agent', 'Unknown'),
            'remote_addr': req.headers.get('X-Forwarded-For', 'Unknown'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if additional_context:
            context.update(additional_context)
            
        # Log request body for debugging (be careful with sensitive data)
        try:
            if req.get_body():
                body = req.get_json()
                if body:
                    # Remove sensitive information
                    safe_body = self._sanitize_request_body(body)
                    context['request_body'] = safe_body
        except (ValueError, UnicodeDecodeError) as e:
            context['request_body_error'] = str(e)
            
        self.logger.info(f"REQUEST_START: {self.function_name}", extra={
            'custom_dimensions': context,
            'operation_id': self.correlation_id
        })
        
    def end_request(self, response: func.HttpResponse, additional_context: Dict[str, Any] = None):
        """Log request end with performance metrics"""
        if self.request_start_time:
            duration = time.time() - self.request_start_time
        else:
            duration = 0
            
        context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'status_code': response.status_code,
            'response_length': len(response.get_body()) if response.get_body() else 0,
            'duration_ms': round(duration * 1000, 2),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if additional_context:
            context.update(additional_context)
            
        # Add performance classification
        if duration > 30:
            context['performance'] = 'SLOW'
        elif duration > 10:
            context['performance'] = 'MODERATE'
        else:
            context['performance'] = 'FAST'
            
        log_level = 'WARNING' if response.status_code >= 400 else 'INFO'
        
        if response.status_code >= 400:
            # Try to extract error details from response
            try:
                error_body = json.loads(response.get_body())
                context['error_details'] = error_body
            except:
                pass
                
        self.logger.log(
            getattr(logging, log_level),
            f"REQUEST_END: {self.function_name} - {response.status_code} ({duration*1000:.2f}ms)",
            extra={
                'custom_dimensions': context,
                'operation_id': self.correlation_id
            }
        )
        
    def log_service_call(self, service: str, operation: str, url: str, 
                        duration: float, status_code: int, 
                        additional_context: Dict[str, Any] = None):
        """Log external service calls"""
        context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'service': service,
            'operation': operation,
            'url': url,
            'duration_ms': round(duration * 1000, 2),
            'status_code': status_code,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if additional_context:
            context.update(additional_context)
            
        # Performance classification for external calls
        if duration > 5:
            context['performance'] = 'SLOW'
        elif duration > 2:
            context['performance'] = 'MODERATE'
        else:
            context['performance'] = 'FAST'
            
        log_level = 'WARNING' if status_code >= 400 else 'INFO'
        
        self.logger.log(
            getattr(logging, log_level),
            f"SERVICE_CALL: {service}.{operation} - {status_code} ({duration*1000:.2f}ms)",
            extra={
                'custom_dimensions': context,
                'operation_id': self.correlation_id
            }
        )
        
    def log_business_event(self, event_type: str, details: Dict[str, Any]):
        """Log business logic events"""
        context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat()
        }
        context.update(details)
        
        self.logger.info(f"BUSINESS_EVENT: {event_type}", extra={
            'custom_dimensions': context,
            'operation_id': self.correlation_id
        })
        
    def log_error(self, error: Exception, context: Dict[str, Any] = None):
        """Log errors with full context and stack trace"""
        error_context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'stack_trace': traceback.format_exc(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if context:
            error_context.update(context)
            
        self.logger.error(f"ERROR: {type(error).__name__}: {str(error)}", extra={
            'custom_dimensions': error_context,
            'operation_id': self.correlation_id
        })
        
    def log_warning(self, message: str, context: Dict[str, Any] = None):
        """Log warnings with context"""
        warning_context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if context:
            warning_context.update(context)
            
        self.logger.warning(f"WARNING: {message}", extra={
            'custom_dimensions': warning_context,
            'operation_id': self.correlation_id
        })
        
    def log_debug(self, message: str, context: Dict[str, Any] = None):
        """Log debug information"""
        debug_context = {
            'correlation_id': self.correlation_id,
            'function': self.function_name,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if context:
            debug_context.update(context)
            
        self.logger.debug(f"DEBUG: {message}", extra={
            'custom_dimensions': debug_context,
            'operation_id': self.correlation_id
        })
        
    def _sanitize_request_body(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from request body for logging"""
        sensitive_keys = ['password', 'secret', 'key', 'token', 'credential']
        
        def sanitize_dict(d):
            if isinstance(d, dict):
                return {
                    k: '***REDACTED***' if any(sensitive in k.lower() for sensitive in sensitive_keys)
                    else sanitize_dict(v) if isinstance(v, (dict, list)) else v
                    for k, v in d.items()
                }
            elif isinstance(d, list):
                return [sanitize_dict(item) for item in d]
            else:
                return d
                
        return sanitize_dict(body)


def performance_monitor(operation_name: str):
    """Decorator to monitor function performance"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            logger = None
            
            # Try to find logger in args
            for arg in args:
                if isinstance(arg, FunctionLogger):
                    logger = arg
                    break
                    
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if logger:
                    logger.log_business_event('PERFORMANCE_MONITOR', {
                        'operation': operation_name,
                        'duration_ms': round(duration * 1000, 2),
                        'status': 'SUCCESS'
                    })
                    
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                if logger:
                    logger.log_business_event('PERFORMANCE_MONITOR', {
                        'operation': operation_name,
                        'duration_ms': round(duration * 1000, 2),
                        'status': 'ERROR',
                        'error': str(e)
                    })
                    
                raise
                
        return wrapper
    return decorator


def log_servicenow_operation(operation: str):
    """Decorator to log ServiceNow operations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(self, *args, **kwargs)
                duration = time.time() - start_time
                
                # Log successful operation
                logging.getLogger('services.servicenow_client').info(
                    f"ServiceNow operation completed: {operation}",
                    extra={
                        'custom_dimensions': {
                            'operation': operation,
                            'duration_ms': round(duration * 1000, 2),
                            'status': 'SUCCESS',
                            'args_count': len(args),
                            'timestamp': datetime.utcnow().isoformat()
                        }
                    }
                )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Log failed operation
                logging.getLogger('services.servicenow_client').error(
                    f"ServiceNow operation failed: {operation} - {str(e)}",
                    extra={
                        'custom_dimensions': {
                            'operation': operation,
                            'duration_ms': round(duration * 1000, 2),
                            'status': 'ERROR',
                            'error': str(e),
                            'error_type': type(e).__name__,
                            'args_count': len(args),
                            'timestamp': datetime.utcnow().isoformat()
                        }
                    }
                )
                
                raise
                
        return wrapper
    return decorator
