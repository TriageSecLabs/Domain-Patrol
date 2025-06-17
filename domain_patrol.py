#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Domain-Patrol: A simple, command-line tool for auditing domain security hygiene.

This tool checks a list of domains for essential security configurations, including
email security records (SPF, DMARC), web security headers, and the presence
of a security.txt file.

Author: Triage Security Labs
Version: 1.0.0
License: MIT
"""

import argparse
import dns.resolver
import requests
from rich.console import Console
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
VERSION = "1.0.0"
# Suppress insecure request warnings for sites with bad SSL certs
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
# User-Agent to avoid blocking
REQUEST_HEADERS = {
    'User-Agent': f'Domain-Patrol/{VERSION} (https://github.com/TriageSecLabs/Domain-Patrol)'
}

# Rich console for pretty printing
console = Console()

# --- Check Functions ---

def check_dns_record(domain, record_type):
    """Checks for the existence of a given DNS record type."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.resolve(domain, record_type)
        return "✅ [green]Present[/green]"
    except dns.resolver.NoAnswer:
        return "❌ [yellow]Missing[/yellow]"
    except dns.resolver.NXDOMAIN:
        return "❌ [red]No such domain[/red]"
    except Exception:
        return "⚠️ [dim]Error[/dim]"

def check_security_txt(domain):
    """Checks for the presence of a security.txt file."""
    urls_to_check = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt"
    ]
    for url in urls_to_check:
        try:
            response = requests.get(url, headers=REQUEST_HEADERS, timeout=5, verify=False)
            if response.status_code == 200 and "Contact:" in response.text:
                return "✅ [green]Found[/green]"
        except requests.RequestException:
            continue
    return "❌ [yellow]Not Found[/yellow]"

def check_http_headers(domain):
    """Checks for key security headers on the domain's web server."""
    headers_to_check = {
        'Strict-Transport-Security': "✅ HSTS",
        'Content-Security-Policy': "✅ CSP",
        'X-Frame-Options': "✅ XFO",
        'X-Content-Type-Options': "✅ XCTO"
    }
    found_headers = []
    try:
        response = requests.get(f"https://{domain}", headers=REQUEST_HEADERS, timeout=5, verify=False)
        for header, short_name in headers_to_check.items():
            if header in response.headers:
                found_headers.append(short_name)
        return ", ".join(found_headers) if found_headers else "❌ [yellow]None[/yellow]"
    except requests.RequestException:
        return "⚠️ [dim]No Response[/dim]"

def audit_domain(domain):
    """Runs all audit checks for a single domain."""
    console.log(f"Auditing [cyan]{domain}[/cyan]...")
    return {
        'Domain': domain,
        'SPF': check_dns_record(domain, 'TXT'),
        'DMARC': check_dns_record(f'_dmarc.{domain}', 'TXT'),
        'security.txt': check_security_txt(domain),
        'HTTP Headers': check_http_headers(domain)
    }

def main():
    """Main function to parse arguments and run the audit."""
    parser = argparse.ArgumentParser(
        description="Domain-Patrol: A tool for auditing domain security hygiene.",
        epilog="Example: python3 domain_patrol.py -f domains.txt -t 10"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to a file containing a list of domains (one per line).")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads to use.")
    parser.add_argument("-v", "--version", action="version", version=f"Domain-Patrol v{VERSION}")
    args = parser.parse_args()

    console.print(f"[bold blue]Domain-Patrol v{VERSION}[/bold blue] by Triage Security Labs", justify="center")
    console.print("-" * 60)

    try:
        with open(args.file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]Error: Input file '{args.file}' not found.[/bold red]")
        return

    if not domains:
        console.print("[bold red]Error: Input file is empty.[/bold red]")
        return
    
    table = Table(title="Domain Security Hygiene Report")
    headers = ['Domain', 'SPF', 'DMARC', 'security.txt', 'HTTP Headers']
    for header in headers:
        table.add_column(header, justify="left", no_wrap=True)

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(audit_domain, domains))

    # Sort results alphabetically by domain
    results.sort(key=lambda x: x['Domain'])

    for res in results:
        table.add_row(res['Domain'], res['SPF'], res['DMARC'], res['security.txt'], res['HTTP Headers'])

    console.print(table)
    console.print("-" * 60)
    console.print(f"Audit complete. Scanned {len(domains)} domains.")

if __name__ == "__main__":
    main()
