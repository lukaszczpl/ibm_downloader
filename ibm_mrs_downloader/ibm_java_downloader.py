#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IBM Java for AIX Downloader
Downloads Java 8 packages from IBM support page
Supports NTLM proxy authentication

USAGE:
    # Try to fetch page directly (requires internet access)
    python ibm_java_downloader.py
    
    # Use local HTML file (save from browser first)
    python ibm_java_downloader.py ibm_java_page.html
    
    # Download specific URLs from file
    python ibm_java_downloader.py --urls urls.txt
"""

import os
import sys
import re
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from configparser import ConfigParser


class JavaLinkParser(HTMLParser):
    """Parser to extract Java download links from IBM support page"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href' and value:
                    # Look for delivery*.dhe.ibm.com links with java8 and tar.gz
                    if 'delivery' in value and 'dhe.ibm.com' in value and 'java8' in value.lower() and 'tar.gz' in value.lower():
                        if value not in self.links:
                            self.links.append(value)


class IBMJavaDownloader:
    """Main downloader class"""
    
    def __init__(self, html_file=None, urls_file=None):
        self.base_url = "https://www.ibm.com/support/pages/ibm-java-aix-reference-fix-only-downloads-categorized-common-groups-fixes"
        self.download_dir = os.path.join("downloads", "java8")
        self.html_file = html_file
        self.urls_file = urls_file
        self.credentials = self._load_credentials()
        self._setup_proxy()
        
    def _load_credentials(self):
        """Load credentials from credentials.ini if exists"""
        creds = {}
        if os.path.exists('credentials.ini'):
            config = ConfigParser()
            config.read('credentials.ini')
            if 'proxy' in config:
                creds['proxy_host'] = config.get('proxy', 'proxy_host', fallback=None)
                creds['proxy_port'] = config.get('proxy', 'proxy_port', fallback=None)
                creds['proxy_user'] = config.get('proxy', 'proxy_user', fallback=None)
                creds['proxy_pass'] = config.get('proxy', 'proxy_pass', fallback=None)
        return creds
    
    def _setup_proxy(self):
        """Setup proxy with NTLM authentication if configured"""
        if self.credentials.get('proxy_host') and self.credentials.get('proxy_port'):
            proxy_url = f"http://{self.credentials['proxy_host']}:{self.credentials['proxy_port']}"
            
            # Setup proxy handler
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url
            })
            
            # Setup authentication if credentials provided
            if self.credentials.get('proxy_user') and self.credentials.get('proxy_pass'):
                # Note: urllib doesn't support NTLM natively, but will attempt basic auth
                # For full NTLM support, would need external library
                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(
                    None,
                    proxy_url,
                    self.credentials['proxy_user'],
                    self.credentials['proxy_pass']
                )
                auth_handler = urllib.request.ProxyBasicAuthHandler(password_mgr)
                opener = urllib.request.build_opener(proxy_handler, auth_handler)
            else:
                opener = urllib.request.build_opener(proxy_handler)
            
            urllib.request.install_opener(opener)
            print(f"Proxy configured: {proxy_url}")
    
    def fetch_page(self):
        """Fetch the IBM support page or read from local file"""
        if self.html_file:
            print(f"Reading HTML from local file: {self.html_file}")
            try:
                with open(self.html_file, 'r', encoding='utf-8', errors='ignore') as f:
                    html = f.read()
                    print(f"File read successfully ({len(html)} bytes)")
                    return html
            except FileNotFoundError:
                print(f"Error: File not found: {self.html_file}")
                sys.exit(1)
            except Exception as e:
                print(f"Error reading file: {e}")
                sys.exit(1)
        else:
            print(f"Fetching page: {self.base_url}")
            try:
                req = urllib.request.Request(
                    self.base_url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                with urllib.request.urlopen(req, timeout=30) as response:
                    html = response.read().decode('utf-8', errors='ignore')
                    print(f"Page fetched successfully ({len(html)} bytes)")
                    return html
            except urllib.error.URLError as e:
                print(f"Error fetching page: {e}")
                print("\nTIP: If you're behind a corporate proxy/firewall:")
                print("  1. Open the URL in your browser:")
                print(f"     {self.base_url}")
                print("  2. Save the page as HTML (Ctrl+S)")
                print("  3. Run: python ibm_java_downloader.py <saved_file.html>")
                sys.exit(1)
    
    def parse_links(self, html):
        """Parse HTML to extract Java download links"""
        parser = JavaLinkParser()
        parser.feed(html)
        
        # Also use regex to find links that might not be in anchor tags
        pattern = r'https?://delivery\d+\.dhe\.ibm\.com/[^\s"\'<>]+java8[^\s"\'<>]*\.tar\.gz'
        regex_links = re.findall(pattern, html, re.IGNORECASE)
        
        all_links = list(set(parser.links + regex_links))
        
        print(f"\nFound {len(all_links)} Java 8 package link(s):")
        for link in all_links:
            print(f"  - {link}")
        
        return all_links
    
    def read_urls_from_file(self):
        """Read URLs from a text file"""
        print(f"Reading URLs from file: {self.urls_file}")
        urls = []
        try:
            with open(self.urls_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Validate URL
                        if 'delivery' in line and 'dhe.ibm.com' in line and 'tar.gz' in line:
                            urls.append(line)
            print(f"Found {len(urls)} URL(s) in file")
            for url in urls:
                print(f"  - {url}")
            return urls
        except FileNotFoundError:
            print(f"Error: File not found: {self.urls_file}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    
    def download_file(self, url):
        """Download a single file"""
        filename = os.path.basename(urllib.parse.urlparse(url).path)
        filepath = os.path.join(self.download_dir, filename)
        
        # Check if file already exists
        if os.path.exists(filepath):
            print(f"\nSkipping {filename} (already downloaded)")
            return True
        
        print(f"\nDownloading: {filename}")
        print(f"From: {url}")
        
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            with urllib.request.urlopen(req, timeout=300) as response:
                total_size = response.headers.get('Content-Length')
                if total_size:
                    total_size = int(total_size)
                    print(f"Size: {total_size / (1024*1024):.2f} MB")
                
                # Download with progress
                downloaded = 0
                block_size = 8192
                
                with open(filepath, 'wb') as f:
                    while True:
                        buffer = response.read(block_size)
                        if not buffer:
                            break
                        downloaded += len(buffer)
                        f.write(buffer)
                        
                        if total_size:
                            progress = (downloaded / total_size) * 100
                            print(f"\rProgress: {progress:.1f}% ({downloaded / (1024*1024):.2f} MB)", end='')
                
                print(f"\n✓ Downloaded successfully: {filename}")
                return True
                
        except Exception as e:
            print(f"\n✗ Error downloading {filename}: {e}")
            # Remove partial download
            if os.path.exists(filepath):
                os.remove(filepath)
            return False
    
    def run(self):
        """Main execution method"""
        print("=" * 70)
        print("IBM Java for AIX Downloader")
        print("=" * 70)
        
        # Create download directory
        os.makedirs(self.download_dir, exist_ok=True)
        print(f"Download directory: {os.path.abspath(self.download_dir)}")
        
        # Get download links
        if self.urls_file:
            # Read URLs directly from file
            links = self.read_urls_from_file()
        else:
            # Fetch and parse page (either from web or local HTML file)
            html = self.fetch_page()
            links = self.parse_links(html)
        
        if not links:
            print("\n⚠ No Java 8 download links found.")
            print("\nYou can manually create a urls.txt file with download links:")
            print("  https://delivery04.dhe.ibm.com/sar/CMA/WSA/0dohn/0/java8_32_installp_8.0.0.860.tar.gz")
            print("  https://delivery04.dhe.ibm.com/sar/CMA/WSA/0dgqj/0/java8_64_installp_8.0.0.855.tar.gz")
            print("\nThen run: python ibm_java_downloader.py --urls urls.txt")
            return
        
        # Download all files
        print(f"\n{'=' * 70}")
        print(f"Starting downloads...")
        print('=' * 70)
        
        success_count = 0
        fail_count = 0
        
        for url in links:
            if self.download_file(url):
                success_count += 1
            else:
                fail_count += 1
        
        # Summary
        print(f"\n{'=' * 70}")
        print("Download Summary")
        print('=' * 70)
        print(f"Total links found: {len(links)}")
        print(f"Successfully downloaded: {success_count}")
        print(f"Failed: {fail_count}")
        print(f"Download directory: {os.path.abspath(self.download_dir)}")


def main():
    """Main entry point"""
    html_file = None
    urls_file = None
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == '--urls' and len(sys.argv) > 2:
            urls_file = sys.argv[2]
        elif arg.startswith('--'):
            print("Usage:")
            print("  python ibm_java_downloader.py")
            print("  python ibm_java_downloader.py <html_file>")
            print("  python ibm_java_downloader.py --urls <urls_file>")
            sys.exit(1)
        else:
            html_file = arg
    
    downloader = IBMJavaDownloader(html_file=html_file, urls_file=urls_file)
    downloader.run()


if __name__ == "__main__":
    main()
