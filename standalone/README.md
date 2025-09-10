# ServiceNow CVE Analyzer

A Python tool to search for CVEs in ServiceNow and get accurate counts of vulnerable systems. Integrates with ServiceNow's Vulnerability Response module to provide quick impact assessment for security vulnerabilities.

## Key Features

- **Accurate vulnerability counts** - Shows both currently vulnerable and historically affected systems
- **System identification** - Lists affected systems with names and IP addresses  
- **Fast analysis** - Uses metadata for counts, only fetches details as needed
- **Export capabilities** - Generates CSV, JSON, and text reports
- **OAuth2 authentication** - Secure integration with ServiceNow

## Quick Start

### 1. Prerequisites

- Python 3.6+
- `requests` library (`pip install requests`)
- ServiceNow instance with Vulnerability Response module
- OAuth2 credentials for ServiceNow

### 2. Configuration

Create a `config.json` file with your ServiceNow credentials:

```json
{
  "instance_url": "https://myinstance.service-now.com",
  "client_id": "your_oauth_client_id",
  "client_secret": "your_oauth_client_secret",
  "username": "your_username",
  "password": "your_password"
}
```

**Important:** Never commit `config.json` to version control. It's already in `.gitignore`.

### 3. Basic Usage

```bash
# Analyze a single CVE
python3 servicenow_cve_analyzer.py CVE-2024-1234

# Analyze multiple CVEs
python3 servicenow_cve_analyzer.py CVE-2024-1234 CVE-2024-5678

# Include patched systems in the count
python3 servicenow_cve_analyzer.py CVE-2024-1234 --include-patched

# Fetch full details for all systems (slower)
python3 servicenow_cve_analyzer.py CVE-2024-1234 --full
```

## Understanding the Output

### Vulnerability Counts

The tool shows two important counts:

- **Currently Vulnerable (Active)**: Systems that still need patching
- **All-Time Total (Inc. Patched)**: All systems ever affected, including those already patched

Example output:
```
📊 VULNERABILITY COUNTS:
   Currently Vulnerable (Active): 4
   All-Time Total (Inc. Patched): 10
   • Qualys QID-110504: 4 active / 10 total
```

This means:
- 4 systems currently need patching
- 6 systems have already been patched
- 10 systems were affected in total

### System Details

The tool displays:
- System name
- IP address
- Issue description
- Vulnerability item number

For large result sets (>10 systems), it shows a sample and exports the full list to files.

## Output Files

Three files are generated for each CVE analysis:

1. **CSV** (`CVE-2024-1234_systems_*.csv`) - Spreadsheet of affected systems
2. **JSON** (`CVE-2024-1234_data_*.json`) - Complete data for programmatic use
3. **TXT** (`CVE-2024-1234_report_*.txt`) - Human-readable summary report

## ServiceNow Setup

### OAuth2 Configuration

1. In ServiceNow, navigate to **System OAuth > Application Registry**
2. Click **New** > **Create an OAuth API endpoint for external clients**
3. Configure the application and note the Client ID and Client Secret
4. Ensure your user account has read access to:
   - `sn_vul_nvd_entry` (NVD entries)
   - `sn_vul_third_party_entry` (Qualys/Tenable data)
   - `sn_vul_vulnerable_item` (Vulnerable items)
   - `cmdb_ci` (Configuration items)

### Required Permissions

Your ServiceNow user needs:
- Read access to Vulnerability Response tables
- Read access to CMDB
- API access enabled

## API Limitations

- ServiceNow API has a limit of 1000 records per query
- For CVEs affecting >1000 systems, the tool shows the accurate total count from metadata
- Use `--full` flag carefully with high-count CVEs as it may be slow

## Command Line Options

```
python3 servicenow_cve_analyzer.py [-h] [-c CONFIG] [--full] [--include-patched] cve_ids [cve_ids ...]

positional arguments:
  cve_ids               CVE ID(s) to analyze

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Config file (default: config.json)
  --full                Fetch full details for all systems (slower)
  --include-patched     Include patched/remediated systems in the count
```

## Example Workflow

1. **Quick impact assessment:**
```bash
python3 servicenow_cve_analyzer.py CVE-2024-1234
```
Shows total count and sample of affected systems.

2. **Track remediation progress:**
```bash
python3 servicenow_cve_analyzer.py CVE-2024-1234 --include-patched
```
Shows both active and patched systems to track progress.

3. **Generate full report:**
```bash
python3 servicenow_cve_analyzer.py CVE-2024-1234 --full
```
Fetches complete details for all affected systems.

## Troubleshooting

### Authentication Errors
- Verify OAuth2 credentials in `config.json`
- Check that OAuth application is active in ServiceNow
- Ensure user account is active and has proper permissions

### No Results Found
- Verify CVE ID format (should be CVE-YYYY-NNNNN)
- Check if vulnerability scanning has been performed in ServiceNow
- Ensure Vulnerability Response module is active

### API Limits
- For large result sets, use the count from metadata (always accurate)
- Consider using `--full` flag only when necessary
- Export files contain all retrieved data even when console shows sample

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues or questions:
- Open an issue on GitHub
- Check ServiceNow Vulnerability Response documentation
- Verify API access and permissions