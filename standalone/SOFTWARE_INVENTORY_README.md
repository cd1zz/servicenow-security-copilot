# ServiceNow Software Inventory Analyzer

A high-performance Python tool to query and analyze software installations from ServiceNow's Configuration Management Database (CMDB). Optimized for large-scale environments with thousands of installations.

## Key Features

- **Wildcard search support** - Search using patterns like `*axon`, `Windows*`, `*Office*`
- **Performance optimized** - Limits API calls while preserving full installation counts
- **Three query modes**:
  - **Balanced (default)** - Full counts with up to 25 sample hosts per version
  - **Fast** - Counts only, no host enumeration
  - **Full details** - Up to 100 hosts per version (slower)
- **Export capabilities** - CSV and JSON export with detailed host mapping
- **Manufacturer search** - Find all software from specific vendors
- **Software name search** - Find specific software across all versions

## Quick Start

### Prerequisites

- Python 3.6+
- `requests` library (`pip install requests`)
- ServiceNow instance with software inventory data
- OAuth2 credentials for ServiceNow
- Access to `cmdb_sam_sw_install` table (optimal) or `cmdb_rel_ci` (fallback)

### Configuration

Use the same `config.json` as the CVE analyzer:

```json
{
  "instance_url": "https://myinstance.service-now.com",
  "client_id": "your_oauth_client_id",
  "client_secret": "your_oauth_client_secret",
  "username": "your_username",
  "password": "your_password"
}
```

### Basic Usage

```bash
# Search by software name with wildcards
python3 software_inventory.py --software "axon*"
python3 software_inventory.py --software "*Office"
python3 software_inventory.py --software "Windows*Server*"

# Search by manufacturer with wildcards
python3 software_inventory.py --manufacturer "*axon"
python3 software_inventory.py --manufacturer "Palo*"
python3 software_inventory.py --manufacturer "Microsoft"

# Performance modes
python3 software_inventory.py --software "axon*"                # Default: balanced mode
python3 software_inventory.py --software "axon*" --no-details   # Fast: counts only
python3 software_inventory.py --software "axon*" --full-details # Slow: all hosts

# Export results
python3 software_inventory.py --software "axon*" --export

# Debug mode
python3 software_inventory.py --software "axon*" --debug
```

## Understanding the Output

### Software Search Output

```
================================================================================
🔍 SEARCHING FOR SOFTWARE: axon*
   Using wildcard search pattern
================================================================================

⚡ Running in balanced mode: Full counts with up to 25 sample hosts per version

Found 17 version(s) of axon*

📊 SOFTWARE INVENTORY - axon*
================================================================================

📈 SUMMARY:
   Software: axon*
   Total Versions: 17
   Total Installations: 2804

📦 VERSION DISTRIBUTION:
------------------------------------------------------------

Version: 3.28.0.10449
   Manufacturer: Tripwire
   Installations: 2173                     <-- Full count preserved
   Sample Hosts (5 of 2173 total):         <-- Shows it's a sample
      • sqlpri22tfsstg (10.250.232.199) - Windows
      • dvprivmho162 (10.251.238.162) - Windows
      • dvprivmho075 (10.251.238.75) - Windows
      • dvprivmds155 (10.251.243.155) - Windows
      • dvprivmds156 (10.251.243.156) - Windows
      ... and 2168 more systems            <-- Indicates more systems exist
```

### Key Information

1. **Total Counts Always Preserved**: The `Installations:` field shows the complete count
2. **Sample Indication**: When showing partial host lists, clearly indicates "Sample Hosts (X of Y total)"
3. **Performance Info**: Shows which mode is running at startup
4. **Wildcard Support**: Automatically detects and uses wildcard patterns

## Performance Optimization

### The Problem
Traditional queries make one API call per host:
- 2,173 installations = 2,173 individual API calls
- Can take 5-10 minutes for large software deployments

### The Solution
Our optimized approach:
- **Balanced mode**: 25 API calls instead of 2,173 (87x faster!)
- **Fast mode**: 1 API call (counts only, no host details)
- **Full details**: Up to 100 API calls (when you need more hosts)

### Query Modes Comparison

| Mode | Flag | API Calls | Speed | Use Case |
|------|------|-----------|-------|----------|
| Balanced | (default) | 25 per version | Fast | General analysis |
| Fast | `--no-details` | 0 (counts only) | Instant | Quick counts |
| Full | `--full-details` | 100 per version | Slower | Detailed analysis |

## Wildcard Search

The tool supports wildcards using the `*` character:

- `*axon` - Ends with "axon"
- `Palo*` - Starts with "Palo"
- `*Office*` - Contains "Office"
- `Windows*Server` - Starts with "Windows" and ends with "Server"

## Export Files

When using `--export`, the tool generates:

1. **CSV** - Spreadsheet with software and host mapping
2. **JSON** - Complete data structure for programmatic use
3. **Host CSV** - Detailed host-to-software mapping

Example: `software_axon_20250910_143022.csv`

## Troubleshooting

### Permission Issues

If you see warnings about `cmdb_sam_sw_install` access:
```
⚠️  Permission denied for cmdb_sam_sw_install table
   This table requires the 'sam_user' or 'asset' role.
```

**Solution**: Request the `sam_user` role from your ServiceNow administrator for optimal performance.

### Testing Access

Run the access test script:
```bash
python3 test_sam_access.py
```

This will verify:
- Authentication is working
- Table access permissions
- Performance implications

### Debug Mode

Use `--debug` to see detailed information:
```bash
python3 software_inventory.py --software "axon*" --debug
```

Shows:
- Which package is being processed
- How many installations were found
- Whether queries are using SAM table or relationships

## API Limits

- Default: 25 hosts per software version
- Maximum: 100 hosts per software version (use `--full-details`)
- Package limit: 1000 software packages per query

## Use Cases

### Security Auditing
Find all installations of potentially vulnerable software:
```bash
python3 software_inventory.py --software "log4j*" --export
```

### License Compliance
Track all software from a specific vendor:
```bash
python3 software_inventory.py --manufacturer "Oracle" --export
```

### Version Management
Identify outdated software versions:
```bash
python3 software_inventory.py --software "Java*" --export
# Review the version distribution in the output
```

### Quick Counts
Get rapid installation counts without host details:
```bash
python3 software_inventory.py --software "*Office*" --no-details
```

## Notes

- The tool uses ServiceNow's LIKE operator for searches
- Wildcard patterns are case-insensitive
- Results are sorted by installation count (highest first)
- Host details are limited by default to improve performance
- Full installation counts are always preserved regardless of mode