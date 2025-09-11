# ServiceNow Vulnerability Analyzer API Documentation

## Overview

This API provides programmatic access to ServiceNow vulnerability data and software inventory information through Azure Functions endpoints.

### ⚠️ Important: ServiceNow Vulnerability States

ServiceNow vulnerability items use different state values across instances:
- **State=1**: Traditional "Open" (rarely used)  
- **State=11**: Common "Open/Active" (frequently used)
- **State=3**: "Closed/Resolved" (universal)

**Our Implementation**: We use `state!=3` (exclude closed) rather than `state=1` to ensure compatibility across all ServiceNow instances.

## OpenAPI Specification

The complete API specification is available in:
- **YAML Format**: [`openapi.yaml`](./openapi.yaml)
- **Interactive Documentation**: Open [`swagger-ui.html`](./swagger-ui.html) in a browser

## Authentication

All API endpoints require authentication using an API key in the request header:

```http
X-API-Key: your-secure-api-key
```

Configure the API key in your Azure Function App settings or `local.settings.json`:

```json
{
  "Values": {
    "API_KEY": "your-secure-api-key"
  }
}
```

## Base URLs

- **Local Development**: `http://localhost:7071/api`
- **Azure Production**: `https://{your-function-app}.azurewebsites.net/api`

## Available Endpoints

### 1. Analyze Single Vulnerability
**POST** `/analyze-vulnerability`

Analyzes a single CVE or QID for vulnerable systems.

#### Request Body
```json
{
  "vuln_id": "CVE-2024-1234",
  "fetch_all_details": false,
  "include_patched": false,
  "confirmation_state": "confirmed"
}
```

#### Response
```json
{
  "status": "success",
  "vuln_id": "CVE-2024-1234",
  "vuln_type": "CVE",
  "summary": "Remote code execution vulnerability",
  "cvss_score": "9.8",
  "statistics": {
    "total_vulnerable_systems": 25,
    "systems_retrieved": 25
  },
  "systems": [...]
}
```

### 2. Batch Analyze Vulnerabilities
**POST** `/batch-analyze`

Analyzes multiple vulnerabilities in parallel.

#### Request Body
```json
{
  "vuln_ids": ["CVE-2024-1234", "CVE-2024-5678", "QID-110504"],
  "parallel": true,
  "fetch_all_details": false
}
```

### 3. Search by Status
**POST** `/status-search`

Searches vulnerabilities by confirmation status.

#### Request Body
```json
{
  "confirmation_state": "confirmed",
  "limit": 100,
  "include_systems": true
}
```

### 4. Software Inventory
**POST** `/software-inventory`

Queries software packages by manufacturer or name.

#### Request Body (Manufacturer Search)
```json
{
  "search_type": "manufacturer",
  "manufacturer": "Palo Alto Networks",
  "fetch_details": true,
  "limit": 100,
  "max_hosts_per_version": 25  // Optional, default 25, max 100
}
```

#### Request Body (Software Search)
```json
{
  "search_type": "software",
  "software_name": "Cortex XDR",
  "fetch_details": true,
  "limit": 50,
  "max_hosts_per_version": 25  // Optional, default 25, max 100
}
```

## Status Codes

| Code | Description |
|------|------------|
| 200 | Success - Request processed successfully |
| 400 | Bad Request - Invalid parameters or missing required fields |
| 401 | Unauthorized - Invalid or missing API key |
| 404 | Not Found - Resource not found (software/vulnerability) |
| 500 | Internal Server Error - Server-side error occurred |

## Rate Limiting

The API follows Azure Functions consumption plan limits:
- **Timeout**: 10 minutes maximum per request
- **Concurrent Requests**: Based on your Azure plan
- **Recommended**: Implement client-side retry logic with exponential backoff

## Error Handling

All error responses follow this format:

```json
{
  "error": "Error message describing what went wrong",
  "details": {
    "additional": "context"
  }
}
```

## Example Client Code

### Python
```python
import requests
import json

# Configuration
API_URL = "http://localhost:7071/api"
API_KEY = "your-api-key"

# Analyze a vulnerability
def analyze_vulnerability(vuln_id):
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    
    payload = {
        "vuln_id": vuln_id,
        "fetch_all_details": False,
        "confirmation_state": "confirmed"
    }
    
    response = requests.post(
        f"{API_URL}/analyze-vulnerability",
        headers=headers,
        json=payload
    )
    
    return response.json()

# Example usage
result = analyze_vulnerability("CVE-2024-1234")
print(f"Found {result['statistics']['total_vulnerable_systems']} vulnerable systems")
```

### JavaScript/Node.js
```javascript
const axios = require('axios');

const API_URL = 'http://localhost:7071/api';
const API_KEY = 'your-api-key';

async function analyzeVulnerability(vulnId) {
    try {
        const response = await axios.post(
            `${API_URL}/analyze-vulnerability`,
            {
                vuln_id: vulnId,
                fetch_all_details: false,
                confirmation_state: 'confirmed'
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY
                }
            }
        );
        
        return response.data;
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
        throw error;
    }
}

// Example usage
analyzeVulnerability('CVE-2024-1234')
    .then(result => {
        console.log(`Found ${result.statistics.total_vulnerable_systems} vulnerable systems`);
    });
```

### PowerShell
```powershell
$ApiUrl = "http://localhost:7071/api"
$ApiKey = "your-api-key"

function Invoke-VulnerabilityAnalysis {
    param(
        [string]$VulnId
    )
    
    $headers = @{
        "Content-Type" = "application/json"
        "X-API-Key" = $ApiKey
    }
    
    $body = @{
        vuln_id = $VulnId
        fetch_all_details = $false
        confirmation_state = "confirmed"
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod `
        -Uri "$ApiUrl/analyze-vulnerability" `
        -Method Post `
        -Headers $headers `
        -Body $body
    
    return $response
}

# Example usage
$result = Invoke-VulnerabilityAnalysis -VulnId "CVE-2024-1234"
Write-Host "Found $($result.statistics.total_vulnerable_systems) vulnerable systems"
```

## Filtering Options

### Confirmation States
- `confirmed` - Confirmed vulnerabilities
- `potential` - All potential vulnerabilities
- `potential-investigation` - Requires investigation
- `potential-patch` - Awaiting patch
- `potential-low` - Low risk
- `none` - No confirmation state set

## Performance Considerations

1. **Use `fetch_all_details: false`** for faster responses when you only need counts
2. **Enable parallel processing** in batch operations when analyzing multiple vulnerabilities
3. **Set reasonable limits** to avoid timeouts on large datasets
4. **Cache responses** when appropriate to reduce API calls

## Deployment

### Local Testing
```bash
# Start the function app locally
func start

# Test with curl
curl -X POST http://localhost:7071/api/analyze-vulnerability \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test-key" \
  -d '{"vuln_id": "CVE-2024-1234"}'
```

### Azure Deployment
```bash
# Deploy to Azure
func azure functionapp publish your-function-app-name

# Set API key in Azure
az functionapp config appsettings set \
  --name your-function-app-name \
  --resource-group your-rg \
  --settings "API_KEY=your-secure-api-key"
```

## Support

For issues or questions:
1. Check the OpenAPI specification for detailed schema information
2. Review error messages in the response body
3. Enable Application Insights for detailed logging
4. Contact your ServiceNow administrator for permission issues

## Version History

- **1.0.0** - Initial release with vulnerability analysis and software inventory endpoints