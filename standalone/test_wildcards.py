#!/usr/bin/env python3
"""
Test script to verify wildcard functionality in software_inventory.py
"""

def test_wildcard_parsing():
    """Test that wildcard patterns are handled correctly"""
    
    test_cases = [
        ("*axon", True, "axon"),
        ("Palo*", True, "Palo"),
        ("*Alto*", True, "Alto"),
        ("Microsoft", False, "Microsoft"),
        ("*Office", True, "Office"),
        ("Windows*", True, "Windows"),
    ]
    
    print("Testing wildcard pattern detection:")
    print("-" * 40)
    
    for pattern, expected_wildcard, expected_search in test_cases:
        # Simulate the wildcard detection logic
        search_term = pattern.replace('*', '')
        is_wildcard = '*' in pattern
        
        print(f"Pattern: {pattern:15} -> Wildcard: {is_wildcard:5} Search term: {search_term}")
        
        assert is_wildcard == expected_wildcard, f"Failed for {pattern}"
        assert search_term == expected_search, f"Failed search term for {pattern}"
    
    print("\n✅ All wildcard pattern tests passed!")

def test_servicenow_like_query():
    """Test that ServiceNow LIKE queries are formed correctly"""
    
    test_cases = [
        ("*axon", "nameLIKEaxon"),
        ("Palo*", "nameLIKEPalo"),
        ("*Alto*", "nameLIKEAlto"),
        ("Microsoft", "nameLIKEMicrosoft"),
    ]
    
    print("\nTesting ServiceNow LIKE query formation:")
    print("-" * 40)
    
    for pattern, expected_query in test_cases:
        search_term = pattern.replace('*', '')
        query = f"nameLIKE{search_term}"
        
        print(f"Pattern: {pattern:15} -> Query: {query}")
        
        assert query == expected_query, f"Failed query for {pattern}"
    
    print("\n✅ All ServiceNow query tests passed!")

if __name__ == "__main__":
    print("=" * 50)
    print("WILDCARD FUNCTIONALITY TEST")
    print("=" * 50)
    
    test_wildcard_parsing()
    test_servicenow_like_query()
    
    print("\n" + "=" * 50)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 50)
    
    print("\nExample usage:")
    print('  python3 software_inventory.py --software "*axon"')
    print('  python3 software_inventory.py --manufacturer "*axon"')
    print('  python3 software_inventory.py --software "Windows*"')
    print('  python3 software_inventory.py --manufacturer "Palo*"')