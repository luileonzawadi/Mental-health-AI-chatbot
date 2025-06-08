#!/usr/bin/env python
# Script to test network connectivity and DNS resolution

import socket
import requests
import sys
import os
from dotenv import load_dotenv

def test_dns_resolution(domain):
    """Test if a domain can be resolved"""
    try:
        print(f"Resolving {domain}...")
        ip = socket.gethostbyname(domain)
        print(f"✓ Successfully resolved {domain} to {ip}")
        return True
    except socket.gaierror as e:
        print(f"✗ Failed to resolve {domain}: {e}")
        return False

def test_http_connection(url):
    """Test if a URL can be accessed"""
    try:
        print(f"Connecting to {url}...")
        response = requests.get(url, timeout=10)
        print(f"✓ Successfully connected to {url} (Status: {response.status_code})")
        return True
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to connect to {url}: {e}")
        return False

def test_proxy_settings():
    """Check and test proxy settings"""
    http_proxy = os.environ.get('HTTP_PROXY')
    https_proxy = os.environ.get('HTTPS_PROXY')
    
    if http_proxy or https_proxy:
        print(f"Proxy settings found:")
        print(f"  HTTP_PROXY: {http_proxy}")
        print(f"  HTTPS_PROXY: {https_proxy}")
        
        # Test with proxies
        proxies = {
            'http': http_proxy,
            'https': https_proxy
        }
        
        try:
            print("Testing connection through proxy...")
            response = requests.get('https://httpbin.org/ip', proxies=proxies, timeout=10)
            print(f"✓ Proxy connection successful: {response.json()}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"✗ Proxy connection failed: {e}")
            return False
    else:
        print("No proxy settings found")
        return None

def main():
    # Load environment variables
    load_dotenv()
    
    print("=== Network Connectivity Test ===\n")
    
    # Test DNS resolution
    domains = [
        'openrouter.ai',
        'api.openai.com',
        'google.com',
        'codewhisperer.us-east-1.amazonaws.com'
    ]
    
    dns_results = []
    for domain in domains:
        result = test_dns_resolution(domain)
        dns_results.append(result)
    
    print("\n=== HTTP Connection Test ===\n")
    
    # Test HTTP connections
    urls = [
        'https://openrouter.ai/api/v1/models',
        'https://www.google.com'
    ]
    
    http_results = []
    for url in urls:
        result = test_http_connection(url)
        http_results.append(result)
    
    print("\n=== Proxy Settings Test ===\n")
    proxy_result = test_proxy_settings()
    
    print("\n=== Summary ===\n")
    print(f"DNS Resolution: {'✓' if all(dns_results) else '✗'}")
    print(f"HTTP Connection: {'✓' if all(http_results) else '✗'}")
    print(f"Proxy Settings: {'✓' if proxy_result is True else '✗' if proxy_result is False else '-'}")
    
    if not all(dns_results) or not all(http_results):
        print("\nRecommendations:")
        if not all(dns_results):
            print("- Check your DNS settings")
            print("- Try using a different DNS server (e.g., 8.8.8.8 or 1.1.1.1)")
        if not all(http_results):
            print("- Check your firewall settings")
            print("- Try setting up HTTP/HTTPS proxies in your .env file")
        
        return 1
    else:
        print("\nAll tests passed successfully!")
        return 0

if __name__ == "__main__":
    sys.exit(main())