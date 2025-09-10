#!/usr/bin/env python3
"""
Test script to check access to cmdb_sam_sw_install table
This table is ideal for software inventory as it directly maps software to hosts
"""

import requests
import json
import sys
import os
import time
from urllib.parse import urljoin


class SAMAccessTester:
    def __init__(self, instance_url: str, client_id: str, client_secret: str, 
                 username: str, password: str):
        """Initialize ServiceNow client with OAuth2 credentials."""
        self.instance_url = instance_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.token_expiry = 0
        
    def get_oauth_token(self) -> str:
        """Get OAuth2 access token."""
        if self.access_token and time.time() < self.token_expiry:
            return self.access_token
            
        token_url = f"{self.instance_url}/oauth_token.do"
        
        data = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.username,
            'password': self.password
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            response = requests.post(token_url, data=data, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"❌ Authentication failed: {e}")
            sys.exit(1)
        
        token_data = response.json()
        self.access_token = token_data['access_token']
        self.token_expiry = time.time() + token_data.get('expires_in', 1800) - 300
        
        return self.access_token
    
    def test_table_access(self, table_name: str, query: str = None):
        """Test access to a specific ServiceNow table."""
        token = self.get_oauth_token()
        url = urljoin(self.instance_url, f'/api/now/table/{table_name}')
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        params = {
            'sysparm_limit': '1',
            'sysparm_fields': 'sys_id'
        }
        
        if query:
            params['sysparm_query'] = query
        
        try:
            response = requests.get(url, headers=headers, params=params)
            return {
                'status_code': response.status_code,
                'accessible': response.status_code == 200,
                'data': response.json() if response.status_code == 200 else None,
                'error': response.text if response.status_code != 200 else None
            }
        except Exception as e:
            return {
                'status_code': None,
                'accessible': False,
                'data': None,
                'error': str(e)
            }
    
    def test_sam_installation_query(self):
        """Test a real query to cmdb_sam_sw_install to see if we can get installation data."""
        token = self.get_oauth_token()
        url = urljoin(self.instance_url, '/api/now/table/cmdb_sam_sw_install')
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Try to get any 5 software installations
        params = {
            'sysparm_limit': '5',
            'sysparm_fields': 'sys_id,software,installed_on,install_date,version',
            'sysparm_query': 'installed_on!=NULL'  # Only get records with hosts
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return {
                    'accessible': True,
                    'record_count': len(data.get('result', [])),
                    'sample_records': data.get('result', [])[:2],  # Show first 2 records
                    'fields_available': list(data['result'][0].keys()) if data.get('result') else []
                }
            else:
                return {
                    'accessible': False,
                    'status_code': response.status_code,
                    'error': response.text[:500] if response.text else 'No error message'
                }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }


def main():
    print("=" * 80)
    print("SERVICENOW TABLE ACCESS TEST")
    print("Testing access to software installation tables")
    print("=" * 80)
    
    # Load config
    config_file = 'config.json'
    if not os.path.exists(config_file):
        print(f"❌ Config file '{config_file}' not found")
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    tester = SAMAccessTester(**config)
    
    print("\n1️⃣ Testing Authentication...")
    try:
        token = tester.get_oauth_token()
        print("   ✅ Authentication successful")
    except Exception as e:
        print(f"   ❌ Authentication failed: {e}")
        sys.exit(1)
    
    print("\n2️⃣ Testing Table Access...")
    print("-" * 40)
    
    # Test different tables
    tables_to_test = [
        ('cmdb_sam_sw_install', 'Software installations (IDEAL for inventory)'),
        ('cmdb_ci_spkg', 'Software packages'),
        ('cmdb_rel_ci', 'CI relationships (fallback option)'),
        ('cmdb_ci', 'Configuration items (hosts)')
    ]
    
    results = {}
    for table, description in tables_to_test:
        print(f"\n📊 Table: {table}")
        print(f"   Description: {description}")
        
        result = tester.test_table_access(table)
        results[table] = result
        
        if result['accessible']:
            print(f"   ✅ ACCESS GRANTED (Status: {result['status_code']})")
            if result['data'] and result['data'].get('result'):
                print(f"   Records found: {len(result['data']['result'])}")
        else:
            print(f"   ❌ ACCESS DENIED (Status: {result['status_code']})")
            if result['status_code'] == 403:
                print(f"   ⚠️  Requires additional role (likely 'sam_user' or 'asset')")
    
    print("\n" + "=" * 80)
    print("3️⃣ DETAILED TEST: cmdb_sam_sw_install")
    print("=" * 80)
    
    if results['cmdb_sam_sw_install']['accessible']:
        print("\n✅ You HAVE access to cmdb_sam_sw_install!")
        print("Testing actual software installation query...")
        
        sam_test = tester.test_sam_installation_query()
        if sam_test['accessible']:
            print(f"\n   Records retrieved: {sam_test['record_count']}")
            if sam_test['fields_available']:
                print(f"   Available fields: {', '.join(sam_test['fields_available'])}")
            
            if sam_test['sample_records']:
                print("\n   Sample installation records:")
                for i, record in enumerate(sam_test['sample_records'], 1):
                    print(f"\n   Record {i}:")
                    for key, value in record.items():
                        # Handle reference fields
                        if isinstance(value, dict) and 'value' in value:
                            print(f"      {key}: {value.get('display_value', value.get('value'))}")
                        else:
                            print(f"      {key}: {value}")
        
        print("\n" + "🎉 " * 20)
        print("GREAT NEWS! You have access to cmdb_sam_sw_install table.")
        print("This means the software inventory script should work efficiently!")
        print("🎉 " * 20)
        
    else:
        print("\n❌ You DO NOT have access to cmdb_sam_sw_install")
        print("\nThis table requires one of these roles:")
        print("  • sam_user")
        print("  • asset")
        print("  • admin")
        print("\n⚠️  The software inventory script will fall back to using")
        print("   cmdb_rel_ci relationships, which may be slower and less detailed.")
        
        print("\n💡 RECOMMENDATION:")
        print("   Request the 'sam_user' role from your ServiceNow administrator")
        print("   to get full access to software installation data.")
    
    print("\n" + "=" * 80)
    print("4️⃣ SUMMARY")
    print("=" * 80)
    
    accessible_tables = [t for t, r in results.items() if r['accessible']]
    denied_tables = [t for t, r in results.items() if not r['accessible']]
    
    print(f"\n✅ Accessible tables ({len(accessible_tables)}):")
    for table in accessible_tables:
        print(f"   • {table}")
    
    if denied_tables:
        print(f"\n❌ Access denied ({len(denied_tables)}):")
        for table in denied_tables:
            print(f"   • {table}")
    
    # Performance implications
    print("\n" + "=" * 80)
    print("5️⃣ PERFORMANCE IMPLICATIONS")
    print("=" * 80)
    
    if results['cmdb_sam_sw_install']['accessible']:
        print("\n✅ OPTIMAL PERFORMANCE")
        print("   With cmdb_sam_sw_install access, queries will be fast because:")
        print("   • Direct software-to-host mapping")
        print("   • Single table query per software package")
        print("   • Includes installation dates and versions")
    else:
        print("\n⚠️  REDUCED PERFORMANCE")
        print("   Without cmdb_sam_sw_install access, queries will be slower because:")
        print("   • Must use relationship tables (cmdb_rel_ci)")
        print("   • Requires multiple queries to resolve relationships")
        print("   • Missing installation dates and some metadata")
        print("\n   Consider using --no-details flag for faster queries")


if __name__ == "__main__":
    main()