# ServiceNow Vulnerability Analyzer - Azure Functions

Azure Functions implementation of the ServiceNow Vulnerability Analyzer, providing serverless API endpoints for vulnerability analysis.

## 📋 Prerequisites

- Azure Functions Core Tools 4.x
- Python 3.8-3.11 (Functions runtime 4.x requirement)
- Azure subscription (for deployment)
- ServiceNow instance with Vulnerability Response module
- OAuth2 credentials for ServiceNow

## 🚀 Quick Start

### 1. Install Azure Functions Core Tools

```bash
# macOS
brew tap azure/functions
brew install azure-functions-core-tools@4

# Windows
winget install Microsoft.Azure.FunctionsCoreTools

# Linux
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-$(lsb_release -cs)-prod $(lsb_release -cs) main" > /etc/apt/sources.list.d/dotnetdev.list'
sudo apt-get update
sudo apt-get install azure-functions-core-tools-4
```

### 2. Configure Local Settings

Copy the template and add your ServiceNow credentials:

```bash
cp local.settings.json.template local.settings.json
```

Edit `local.settings.json` with your ServiceNow OAuth2 credentials:

```json
{
  "Values": {
    "SERVICENOW_INSTANCE_URL": "https://your-instance.service-now.com",
    "SERVICENOW_CLIENT_ID": "your-oauth-client-id",
    "SERVICENOW_CLIENT_SECRET": "your-oauth-client-secret",
    "SERVICENOW_USERNAME": "your-username",
    "SERVICENOW_PASSWORD": "your-password"
  }
}
```

### 3. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Run Locally

```bash
func start
```

The functions will be available at:
- http://localhost:7071/api/analyze-vulnerability
- http://localhost:7071/api/batch-analyze
- http://localhost:7071/api/status-search
- http://localhost:7071/api/software-inventory

## 📚 API Endpoints

### 1. Analyze Single Vulnerability

**POST** `/api/analyze-vulnerability`

Analyze a single CVE or QID for vulnerable systems.

```bash
curl -X POST http://localhost:7071/api/analyze-vulnerability \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_id": "CVE-2024-1234",
    "fetch_all_details": false,
    "include_patched": false,
    "confirmation_state": "confirmed"
  }'
```

**Request Body:**
```json
{
  "vuln_id": "CVE-2024-1234",      // Required: CVE ID or QID
  "fetch_all_details": false,       // Optional: Fetch all system details
  "include_patched": false,         // Optional: Include patched systems
  "confirmation_state": "confirmed" // Optional: Filter by state
}
```

**Response:**
```json
{
  "vulnerability": "CVE-2024-1234",
  "active_count": 5,
  "total_count": 10,
  "systems": [...],
  "metadata": {...}
}
```

### 2. Batch Analyze Multiple Vulnerabilities

**POST** `/api/batch-analyze`

Analyze multiple vulnerabilities in parallel.

```bash
curl -X POST http://localhost:7071/api/batch-analyze \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_ids": ["CVE-2024-1234", "CVE-2024-5678", "QID-110504"],
    "parallel": true
  }'
```

**Request Body:**
```json
{
  "vuln_ids": ["CVE-2024-1234", "QID-123456"],  // Required: Array of IDs
  "fetch_all_details": false,                   // Optional
  "include_patched": false,                     // Optional
  "confirmation_state": "confirmed",            // Optional
  "parallel": true                              // Optional: Process in parallel
}
```

### 3. Search by Vulnerability Status

**POST** `/api/status-search`

Search for vulnerabilities by confirmation status.

```bash
curl -X POST http://localhost:7071/api/status-search \
  -H "Content-Type: application/json" \
  -d '{
    "confirmation_state": "confirmed",
    "limit": 100
  }'
```

**Request Body:**
```json
{
  "confirmation_state": "confirmed",  // Required: Status to search
  "limit": 100,                       // Optional: Max results (default 100)
  "include_systems": true             // Optional: Include system details
}
```

### 4. Software Inventory Search

**POST** `/api/software-inventory`

Query software installations by manufacturer or software name with performance-optimized host enumeration.

```bash
# Search by software name
curl -X POST http://localhost:7071/api/software-inventory \
  -H "Content-Type: application/json" \
  -d '{
    "search_type": "software",
    "software_name": "Cortex XDR",
    "fetch_details": true,
    "max_hosts_per_version": 25
  }'

# Search by manufacturer
curl -X POST http://localhost:7071/api/software-inventory \
  -H "Content-Type: application/json" \
  -d '{
    "search_type": "manufacturer",
    "manufacturer": "Palo Alto Networks",
    "fetch_details": true,
    "max_hosts_per_version": 25
  }'
```

**Request Body:**
```json
{
  "search_type": "manufacturer" | "software",     // Required: Type of search
  "manufacturer": "Palo Alto Networks",           // Required if search_type is manufacturer
  "software_name": "Cortex XDR",                  // Required if search_type is software
  "fetch_details": true,                          // Optional: Fetch host details (default true)
  "limit": 100,                                   // Optional: Max packages to return (default 1000)
  "max_hosts_per_version": 25                     // Optional: Max hosts per version (default 25, max 100)
}
```

**Performance Optimization:**
- Default mode limits to 25 hosts per version while preserving full installation counts
- Set `fetch_details: false` for counts only (fastest)
- Adjust `max_hosts_per_version` up to 100 for more host details

**Response includes:**
- Full installation counts (always preserved)
- Sample host details (limited by `max_hosts_per_version`)
- Metadata indicating if results are sampled
- Version distribution with manufacturer information

## 🔒 Security Configuration

### Using Azure Key Vault (Recommended for Production)

1. Set environment variables in Azure:
```bash
USE_KEY_VAULT=true
KEY_VAULT_URL=https://your-keyvault.vault.azure.net/
```

2. Store secrets in Key Vault:
```bash
az keyvault secret set --vault-name your-keyvault \
  --name "servicenow-instance-url" \
  --value "https://your-instance.service-now.com"

az keyvault secret set --vault-name your-keyvault \
  --name "servicenow-client-id" \
  --value "your-client-id"

# Repeat for other secrets...
```

3. Enable Managed Identity for the Function App:
```bash
az functionapp identity assign --name your-function-app \
  --resource-group your-resource-group
```

4. Grant Key Vault access to the Managed Identity:
```bash
az keyvault set-policy --name your-keyvault \
  --object-id <managed-identity-object-id> \
  --secret-permissions get list
```

### API Key Authentication (Optional)

Add an API key to `local.settings.json`:
```json
{
  "Values": {
    "API_KEY": "your-secure-api-key"
  }
}
```

Then include in requests:
```bash
curl -X POST http://localhost:7071/api/analyze-vulnerability \
  -H "X-API-Key: your-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{"vuln_id": "CVE-2024-1234"}'
```

## 🚢 Deployment to Azure

### 1. Create Function App

```bash
# Create resource group
az group create --name servicenow-analyzer-rg --location eastus

# Create storage account
az storage account create \
  --name snanalyzerstorage \
  --resource-group servicenow-analyzer-rg \
  --location eastus \
  --sku Standard_LRS

# Create function app
az functionapp create \
  --name servicenow-analyzer \
  --storage-account snanalyzerstorage \
  --resource-group servicenow-analyzer-rg \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.9 \
  --functions-version 4
```

### 2. Configure Application Settings

```bash
# Set ServiceNow credentials
az functionapp config appsettings set \
  --name servicenow-analyzer \
  --resource-group servicenow-analyzer-rg \
  --settings \
  "SERVICENOW_INSTANCE_URL=https://your-instance.service-now.com" \
  "SERVICENOW_CLIENT_ID=your-client-id" \
  "SERVICENOW_CLIENT_SECRET=your-secret" \
  "SERVICENOW_USERNAME=your-username" \
  "SERVICENOW_PASSWORD=your-password"
```

### 3. Deploy the Functions

```bash
func azure functionapp publish servicenow-analyzer
```

## 📊 Monitoring

### Application Insights

1. Enable Application Insights:
```bash
az monitor app-insights component create \
  --app servicenow-analyzer-insights \
  --location eastus \
  --resource-group servicenow-analyzer-rg
```

2. Connect to Function App:
```bash
az functionapp config appsettings set \
  --name servicenow-analyzer \
  --resource-group servicenow-analyzer-rg \
  --settings "APPLICATIONINSIGHTS_CONNECTION_STRING=InstrumentationKey=<your-key>"
```

### View Logs

```bash
# Stream logs
func azure functionapp logstream servicenow-analyzer

# View specific function logs
az monitor app-insights query \
  --app servicenow-analyzer-insights \
  --query "traces | where operation_Name == 'analyze-vulnerability'"
```

## 🔧 Configuration Options

### Timeout Settings

Edit `host.json` to adjust function timeout (max 10 minutes on Consumption plan):

```json
{
  "functionTimeout": "00:10:00"
}
```

### Scaling Configuration

For high-volume scenarios, consider:

1. **Premium Plan**: Better performance, VNet integration
2. **Dedicated Plan**: Predictable pricing, longer timeouts
3. **Durable Functions**: For long-running workflows

## 📝 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SERVICENOW_INSTANCE_URL` | ServiceNow instance URL | Yes |
| `SERVICENOW_CLIENT_ID` | OAuth2 Client ID | Yes |
| `SERVICENOW_CLIENT_SECRET` | OAuth2 Client Secret | Yes |
| `SERVICENOW_USERNAME` | ServiceNow username | Yes |
| `SERVICENOW_PASSWORD` | ServiceNow password | Yes |
| `USE_KEY_VAULT` | Enable Azure Key Vault | No |
| `KEY_VAULT_URL` | Azure Key Vault URL | If USE_KEY_VAULT=true |
| `API_KEY` | API key for authentication | No |
| `FUNCTIONS_WORKER_RUNTIME` | Set to "python" | Yes |
| `FUNCTIONS_EXTENSION_VERSION` | Set to "~4" | Yes |

## 🐛 Troubleshooting

### Function not starting

1. Check Python version (3.8-3.11 required):
```bash
python --version
```

2. Verify Azure Functions Core Tools version:
```bash
func --version
```

3. Check local.settings.json exists and is valid JSON

### Authentication errors

1. Verify ServiceNow OAuth2 credentials
2. Check OAuth application is active in ServiceNow
3. Ensure user has proper permissions

### Performance issues

1. Enable Application Insights for detailed telemetry
2. Consider using Premium plan for better performance
3. Implement caching for frequently accessed data

## 📚 Additional Resources

- [Azure Functions Python Developer Guide](https://docs.microsoft.com/en-us/azure/azure-functions/functions-reference-python)
- [ServiceNow REST API Documentation](https://docs.servicenow.com/bundle/rome-application-development/page/integrate/inbound-rest/concept/c_RESTAPI.html)
- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)

## 📄 License

MIT License - See LICENSE file for details