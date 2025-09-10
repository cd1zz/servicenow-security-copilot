# Enhanced Azure Function Logging Configuration

This document explains the comprehensive logging enhancements added to your ServiceNow Security Copilot Function App for debugging issues in Azure.

## Overview

The function app now includes:
- **Structured logging** with custom dimensions
- **Performance tracking** for all operations
- **Request/response correlation** with unique IDs
- **Detailed error context** with stack traces
- **Business event tracking** for key operations
- **ServiceNow API call monitoring**

## Logging Components

### 1. Enhanced host.json Configuration

The `host.json` file has been updated with:
- **Debug-level logging** for all function modules
- **Application Insights integration** with dependency tracking
- **Performance counters** collection
- **Health monitoring** configuration
- **Retry policies** for failed operations

Key logging settings:
```json
{
  "logLevel": {
    "default": "Information",
    "services": "Debug",
    "analyze-vulnerability": "Debug",
    "batch-analyze": "Debug",
    "status-search": "Debug",
    "software-inventory": "Debug"
  }
}
```

### 2. FunctionLogger Utility

A comprehensive logging utility (`services/logging_utils.py`) provides:

#### Key Features:
- **Correlation IDs** for tracking requests across function calls
- **Performance monitoring** with automatic timing
- **Structured custom dimensions** for Azure Log Analytics
- **Automatic request/response logging**
- **Error context capture** with full stack traces

#### Usage in Functions:
```python
from services.logging_utils import FunctionLogger

function_logger = FunctionLogger(__name__)

# Start request logging
function_logger.start_request(req, {'function_name': 'analyze-vulnerability'})

# Log business events
function_logger.log_business_event('VULNERABILITY_ANALYSIS_START', {
    'vuln_id': vuln_id,
    'parameters': {...}
})

# End request logging
function_logger.end_request(response, {'success': True})
```

### 3. ServiceNow Client Enhancement

The ServiceNow client now includes:
- **OAuth token acquisition logging** with timing
- **API request/response monitoring** with performance metrics
- **Permission error tracking** with specific table access issues
- **Company lookup caching** with cache hit/miss tracking
- **Detailed error context** for all ServiceNow operations

### 4. Function-Specific Enhancements

Each function now logs:

#### Analyze Vulnerability Function:
- Parameter validation with context
- ServiceNow client initialization timing
- Vulnerability analysis phases with performance metrics
- System retrieval progress and statistics
- Response formatting timing

#### Batch Analyze Function:
- Batch size and processing strategy
- Parallel vs sequential processing metrics
- Individual vulnerability analysis tracking
- Task completion and failure rates
- Performance comparison between processing modes

#### Status Search Function:
- Confirmation state validation
- Search parameter logging
- Results statistics and timing
- Top vulnerabilities and systems analysis

#### Software Inventory Function:
- Search type validation and parameters
- Manufacturer company lookup with timing
- Software package discovery metrics
- Installation details retrieval timing
- Permission warning tracking

## Viewing Logs in Azure

### 1. Azure Portal Function Logs

Navigate to your Function App in Azure Portal:
1. Go to **Functions** → Select your function
2. Click **Monitor** to view logs
3. Use **Live Metrics** for real-time monitoring

### 2. Application Insights Queries

Use these KQL queries in Application Insights to analyze your logs:

#### View All Function Requests:
```kql
requests
| where cloud_RoleName == "your-function-app-name"
| order by timestamp desc
| project timestamp, name, duration, resultCode, customDimensions
```

#### Track Specific Vulnerability Analysis:
```kql
traces
| where customDimensions.vuln_id == "CVE-2024-1234"
| order by timestamp asc
| project timestamp, message, customDimensions
```

#### Monitor ServiceNow API Performance:
```kql
traces
| where message contains "SERVICE_CALL"
| extend duration_ms = todecimal(customDimensions.duration_ms)
| summarize avg(duration_ms), max(duration_ms), count() by customDimensions.service, customDimensions.operation
```

#### Find Errors and Exceptions:
```kql
traces
| where severityLevel >= 3  // Warning and above
| order by timestamp desc
| project timestamp, message, severityLevel, customDimensions
```

#### Track Business Events:
```kql
traces
| where message contains "BUSINESS_EVENT"
| extend event_type = tostring(customDimensions.event_type)
| summarize count() by event_type, bin(timestamp, 1h)
```

#### Monitor Function Performance:
```kql
traces
| where message contains "REQUEST_END"
| extend duration_ms = todecimal(customDimensions.duration_ms)
| extend function_name = tostring(customDimensions.function)
| summarize avg(duration_ms), max(duration_ms), count() by function_name
| order by avg_duration_ms desc
```

### 3. Custom Dashboard Queries

#### Function Success Rate:
```kql
requests
| summarize 
    Total = count(),
    Success = countif(success == true),
    Failed = countif(success == false)
    by name
| extend SuccessRate = round((Success * 100.0) / Total, 2)
```

#### Top Slowest Operations:
```kql
traces
| where message contains "PERFORMANCE_MONITOR" or message contains "SERVICE_CALL"
| extend duration_ms = todecimal(customDimensions.duration_ms)
| top 20 by duration_ms desc
| project timestamp, message, duration_ms, customDimensions.operation
```

#### Permission Issues Tracking:
```kql
traces
| where message contains "Permission denied" or message contains "Access denied"
| summarize count() by customDimensions.table, customDimensions.endpoint
```

## Debugging Common Issues

### 1. ServiceNow Authentication Problems
Look for logs with:
- `Authentication failed`
- `OAuth token request`
- `TOKEN_EXPIRY` events

### 2. API Permission Issues
Search for:
- `Permission denied`
- `Access denied`
- `403` status codes
- `permission_warnings` in custom dimensions

### 3. Performance Issues
Monitor:
- Functions taking >30 seconds
- ServiceNow API calls >5 seconds
- High memory usage patterns
- Timeout errors

### 4. Data Quality Issues
Track:
- `not_found` vulnerabilities
- Empty result sets
- Malformed responses
- Validation errors

## Log Retention and Alerting

### Setting Up Alerts

Create alerts in Azure Monitor for:

1. **High Error Rate:**
```kql
requests
| where success == false
| summarize ErrorRate = count() by bin(timestamp, 5m)
| where ErrorRate > 5
```

2. **Slow Performance:**
```kql
requests
| where duration > 30000  // 30 seconds
| summarize count() by bin(timestamp, 5m)
```

3. **ServiceNow API Issues:**
```kql
traces
| where message contains "SERVICE_CALL" and customDimensions.status_code >= 400
| summarize count() by bin(timestamp, 5m)
```

### Log Retention

- **Application Insights:** 90 days by default
- **Function logs:** 30 days by default
- **Custom tables:** Configure based on needs

## Best Practices

1. **Use correlation IDs** to track requests across function calls
2. **Monitor custom dimensions** for business-specific metrics
3. **Set up alerts** for critical error conditions
4. **Use performance metrics** to optimize function execution
5. **Regular review** of permission warnings and errors
6. **Archive important logs** for compliance and historical analysis

## Security Considerations

The logging system automatically:
- **Sanitizes sensitive data** from request bodies
- **Truncates long messages** to prevent log flooding
- **Redacts credentials** in connection strings
- **Limits personally identifiable information** in logs

## Support and Troubleshooting

When reporting issues, include:
1. **Correlation ID** from the request
2. **Timestamp** of the issue
3. **Function name** and version
4. **Relevant log excerpts** from Application Insights
5. **Custom dimensions** that show the context

This enhanced logging system provides comprehensive visibility into your Function App's behavior, making it much easier to debug issues and optimize performance in Azure.
