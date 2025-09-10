# ServiceNow Security Copilot

A comprehensive security analysis toolkit for ServiceNow environments, providing vulnerability assessment and software inventory capabilities through both standalone scripts and serverless Azure Functions.

## 🎯 Overview

This toolkit helps security teams:
- **Analyze CVE vulnerabilities** - Get accurate counts of vulnerable systems and identify affected hosts
- **Track software inventory** - Query installed software by vendor or name with performance-optimized enumeration
- **Assess security impact** - Quickly determine the scope of vulnerabilities in your environment
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

# Test the API
curl -X POST http://localhost:7071/api/software-inventory \
  -H "Content-Type: application/json" \
  -d '{"search_type": "software", "software_name": "Office"}'
```

[Full Function App Documentation →](function-app/README.md)

## 🔑 Key Features

### Vulnerability Analysis
- **Accurate counts** - Shows both currently vulnerable and historically affected systems
- **System details** - Lists affected hosts with names, IPs, and vulnerability status
- **Batch processing** - Analyze multiple CVEs simultaneously
- **Export options** - Generate CSV, JSON, and text reports

### Software Inventory
- **Wildcard search** - Use patterns like `*Office`, `Windows*`, `*Server*`
- **Performance optimized** - 87x faster queries with intelligent host sampling
- **Full counts preserved** - Always shows total installations regardless of sampling
- **Flexible modes**:
  - Balanced (default): Full counts + 25 sample hosts
  - Fast: Counts only, no host details
  - Full: Up to 100 hosts per version

## ⚙️ Prerequisites

### For Both Options
- ServiceNow instance with appropriate modules:
  - Vulnerability Response (for CVE analysis)
  - Software Asset Management (for inventory)
- OAuth2 credentials for ServiceNow API access
- Network access to ServiceNow instance

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

## 📊 Performance Optimization

The software inventory tools are optimized for large-scale environments:

| Query Type | Traditional Approach | Our Approach | Improvement |
|------------|---------------------|--------------|-------------|
| 2,173 installations | 2,173 API calls | 25 API calls | **87x faster** |
| 10,000 installations | 10,000 API calls | 25 API calls | **400x faster** |

This is achieved through:
- Intelligent host sampling (configurable limit)
- Batch API queries for host details
- Caching of frequently accessed data
- Parallel processing where possible

## 🔒 Security Considerations

- **Never commit credentials** - Config files are in `.gitignore`
- **Use environment variables** in production
- **Enable API authentication** for function apps
- **Use Azure Key Vault** for production deployments
- **Apply least privilege** - Request only necessary ServiceNow roles

### Required ServiceNow Roles

- **Vulnerability analysis**: `sn_vul_read` or `sn_vul_admin`
- **Software inventory (optimal)**: `sam_user` or `asset`
- **Software inventory (basic)**: Read access to CMDB

## 📚 Documentation

- [Standalone Scripts Documentation](standalone/README.md)
  - [Software Inventory Guide](standalone/SOFTWARE_INVENTORY_README.md)
- [Azure Functions Documentation](function-app/README.md)
  - [API Documentation](function-app/API_DOCUMENTATION.md)

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

**Built with ❤️ for ServiceNow security teams**