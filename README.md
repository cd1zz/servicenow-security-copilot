# ServiceNow Security Copilot

A comprehensive security analysis toolkit for ServiceNow environments, providing vulnerability assessment and software inventory capabilities through both standalone scripts and serverless Azure Functions.

## 🎯 Overview

This toolkit helps security teams:
- **Analyze vulnerabilities** - Query both CVEs and Qualys QIDs to get accurate counts of vulnerable systems
- **Track software inventory** - Query installed software by vendor or name with performance-optimized enumeration
- **Direct ServiceNow integration** - Generate clickable URLs to view vulnerabilities directly in ServiceNow
- **Scanner integration** - Works with Qualys, Tenable, and other vulnerability scanners via ServiceNow's third-party entries
- **Automate security workflows** - Use standalone scripts or deploy as serverless APIs

## 📁 Project Structure

```
servicenow-security-copilot/
├── standalone/              # Python scripts for direct command-line usage
│   ├── servicenow_cve_analyzer.py       # CVE vulnerability analyzer
│   ├── software_inventory.py            # Software inventory analyzer
│   └── software_inventory_optimized.py  # Performance-optimized version
│
└── function-app/           # Azure Functions for serverless API deployment
    ├── analyze-vulnerability/    # Single CVE analysis endpoint
    ├── batch-analyze/            # Multiple CVE analysis endpoint
    ├── software-inventory/       # Software inventory endpoint
    └── status-search/            # Vulnerability status search endpoint
```

## 🚀 Quick Start

### Option 1: Standalone Scripts (Simple & Direct)

Best for: Ad-hoc analysis, automation scripts, CI/CD pipelines

```bash
cd standalone/

# Analyze a CVE
python3 servicenow_cve_analyzer.py CVE-2024-1234

# Analyze a Qualys QID
python3 servicenow_cve_analyzer.py QID-92307
# Or just the numeric ID
python3 servicenow_cve_analyzer.py 92307

# Search software inventory
python3 software_inventory.py --software "Windows*"
python3 software_inventory.py --manufacturer "Microsoft"
```

[Full Standalone Documentation →](standalone/README.md)

### Option 2: Azure Functions (Scalable API)

Best for: Production deployments, web applications, microservices

```bash
cd function-app/

# Run locally
func start

# Test vulnerability analysis
curl -X POST http://localhost:7071/api/analyze-vulnerability \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"vuln_id": "QID-92307", "fetch_all_details": false}'
```

[Full Function App Documentation →](function-app/README.md)

## 📋 Example Output

When analyzing a vulnerability, you'll receive:
```json
{
  "vuln_id": "QID-92307",
  "total_vulnerable_systems": 142,
  "servicenow_url": "https://your-instance.service-now.com/now/nav/ui/classic/params/target/...",
  "systems": [
    {"name": "SERVER01", "ip_address": "10.0.1.5", "assignment_group": "Windows Team"},
    {"name": "SERVER02", "ip_address": "10.0.1.6", "assignment_group": "Linux Team"}
  ]
}
```

## 🔑 Key Features

### Vulnerability Analysis
- **Multiple sources** - Supports both CVE (NVD) and QID (Qualys) vulnerability identifiers
- **Accurate counts** - Shows currently vulnerable systems (sample of 10 for performance)
- **Direct links** - Generates ServiceNow URLs to view vulnerability details in your instance
- **Batch processing** - Analyze multiple CVEs/QIDs simultaneously
- **Export options** - Generate CSV, JSON, and text reports with ServiceNow URLs included
- **Scanner integration** - Leverages ServiceNow's third-party vulnerability entries from Qualys, Tenable, etc.

### Software Inventory  
- **Wildcard search** - Use patterns like `*Office`, `Windows*`, `*Server*`
- **Performance optimized** - Up to 400x faster with intelligent sampling
- **Accurate counts** - Always shows total installations regardless of sampling
- **Flexible modes**:
  - Balanced: Full counts + 25 sample hosts
  - Fast: Counts only, no host details  
  - Full: Up to 100 hosts per version

## ⚙️ Prerequisites

### For Both Options
- ServiceNow instance with:
  - Vulnerability Response module
  - Software Asset Management module
  - Third-party vulnerability data (Qualys/Tenable integration)
- OAuth2 credentials with appropriate permissions
- Network access to ServiceNow APIs

### Standalone Scripts
- Python 3.6+
- `requests` library

### Azure Functions
- Azure Functions Core Tools 4.x
- Python 3.8-3.11
- Azure subscription (for cloud deployment)

## 📋 Configuration

### 1. ServiceNow OAuth Setup

1. Navigate to **System OAuth > Application Registry** in ServiceNow
2. Click **New** > **Create an OAuth API endpoint for external clients**
3. Configure the application and note:
   - Client ID
   - Client Secret
   - Instance URL

### 2. Configure Credentials

#### For Standalone Scripts

Create `standalone/config.json`:
```json
{
  "instance_url": "https://your-instance.service-now.com",
  "client_id": "your-oauth-client-id",
  "client_secret": "your-oauth-client-secret",
  "username": "your-username",
  "password": "your-password"
}
```

#### For Azure Functions

Create `function-app/local.settings.json`:
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

## 📊 Performance & Integration

### Qualys/Scanner Integration
The toolkit leverages ServiceNow's built-in integration with vulnerability scanners:
- **QID Support** - Query Qualys vulnerability IDs directly (e.g., QID-92307)
- **CVE Mapping** - Automatically finds associated QIDs for CVE queries
- **Scanner Sources** - Works with data from Qualys, Tenable, Rapid7, etc.
- **Direct Links** - Generate clickable URLs to ServiceNow vulnerability views

### Performance Optimization
Both vulnerability and software queries are optimized:
- **Smart sampling** - Returns 10 vulnerable systems for quick assessment
- **Batch processing** - Analyze multiple vulnerabilities in parallel
- **Intelligent caching** - Reduces redundant API calls by up to 400x

## 🔒 Security Considerations

- **Never commit credentials** - Config files are in `.gitignore`
- **Use environment variables** in production
- **Enable API authentication** for function apps
- **Use Azure Key Vault** for production deployments
- **Apply least privilege** - Request only necessary ServiceNow roles

### Required ServiceNow Roles

- **Vulnerability analysis**: `sn_vul_read` (minimum) or `sn_vul_admin`
- **Software inventory**: `sam_user` or `asset` role
- **CMDB access**: Read permissions for configuration items

## 📚 Documentation

- [Standalone Scripts Documentation](standalone/README.md)
- [Azure Functions Documentation](function-app/README.md)
- [API Reference](function-app/API_DOCUMENTATION.md)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details

## ⚠️ Disclaimer

This tool is provided as-is for security analysis purposes. Always:
- Test in non-production environments first
- Verify results before taking action
- Follow your organization's security policies
- Respect rate limits and API quotas

## 🆘 Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check existing documentation
- Review ServiceNow API documentation

---

**Built for ServiceNow security teams managing Qualys and other vulnerability scanners**