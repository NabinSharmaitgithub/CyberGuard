import argparse
import sys
from typing import List, Dict, Any
from urllib.parse import urlparse

from tqdm import tqdm

from modules.report import print_report, add_finding
from modules.port_scan import tcp_port_scan, get_host_ip
from modules.headers import check_security_headers
from modules.sqli import check_sqli
from modules.xss import check_xss
from modules.version_scan import check_version
from modules.database_scan import check_databases
from modules.admin_panel_scan import check_admin_panels
from modules.sniffer import sniff
from modules.bruteforce import ssh_bruteforce
from modules.sitemapper import map_site
from modules.find_connected import get_active_hosts, get_interfaces

# Default ports to scan
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

def main():
    parser = argparse.ArgumentParser(description="A simple vulnerability scanner.")
    parser.add_argument("--target", help="The target URL or IP address.")
    parser.add_argument("--output", default="text", choices=["text", "json"], help="The output format.")
    parser.add_argument("--ports", help="A comma-separated list of ports to scan.")
    parser.add_argument("--timeout", type=float, default=1.0, help="The timeout for network requests in seconds.")
    parser.add_argument("--aggressive", action="store_true", help="Perform more intensive (but still safe) checks.")
    parser.add_argument("--deep", action="store_true", help="Perform deep scans for databases and admin panels.")
    parser.add_argument("--i-have-permission", action="store_true", help="Required for aggressive scans.")
    parser.add_argument("--web", action="store_true", help="Launch the web GUI.")
    parser.add_argument("--sniff", action="store_true", help="Sniff network packets.")
    parser.add_argument("--bruteforce-ssh", action="store_true", help="Perform SSH bruteforce attack on the target.")
    parser.add_argument("--user", help="A single username for bruteforce.")
    parser.add_argument("--user-list", help="Path to a file containing a list of usernames for bruteforce.")
    parser.add_argument("--password", help="A single password for bruteforce.")
    parser.add_argument("--pass-list", help="Path to a file containing a list of passwords for bruteforce.")
    parser.add_argument("--sitemap", action="store_true", help="Perform site mapping on the target URL.")
    parser.add_argument("--wordlist", help="Path to a file containing a list of words for site mapping.")
    parser.add_argument("--extensions", help="A comma-separated list of extensions for site mapping.")
    parser.add_argument("--find-connected", help="Discover active hosts on the local network. Provide the network interface.")
    parser.add_argument("--internal", action="store_true", help="List internal tools.")

    args = parser.parse_args()

    if args.web:
        from web_gui import main as web_main
        web_main()
        sys.exit(0)

    if args.sniff:
        if not args.target:
            print("The --target argument is required for sniffing.")
            sys.exit(1)
        print("Starting network sniffer...")
        output = sniff(args.target)
        print(output)
        sys.exit(0)

    if args.bruteforce_ssh:
        if not args.target:
            print("The --target argument is required for SSH bruteforce.")
            sys.exit(1)

        usernames = []
        if args.user:
            usernames.append(args.user)
        elif args.user_list:
            with open(args.user_list) as f:
                usernames = [line.strip() for line in f]
        else:
            print("Either --user or --user-list is required for SSH bruteforce.")
            sys.exit(1)

        passwords = []
        if args.password:
            passwords.append(args.password)
        elif args.pass_list:
            with open(args.pass_list) as f:
                passwords = [line.strip() for line in f]
        else:
            print("Either --password or --pass-list is required for SSH bruteforce.")
            sys.exit(1)

        print(f"Starting SSH bruteforce on {args.target}...")
        credentials = ssh_bruteforce(args.target, usernames, passwords)
        if credentials:
            print(f"Success! Found credentials: {credentials[0]}:{credentials[1]}")
        else:
            print("Failed to find credentials.")
        sys.exit(0)

    if args.sitemap:
        if not args.target:
            print("The --target argument is required for site mapping.")
            sys.exit(1)

        if not args.wordlist:
            print("The --wordlist argument is required for site mapping.")
            sys.exit(1)

        with open(args.wordlist) as f:
            wordlist = [line.strip() for line in f]

        extensions = []
        if args.extensions:
            extensions = [ext.strip() for ext in args.extensions.split(",")]
        else:
            extensions = ["", ".html", ".php", ".js", ".txt"]

        print(f"Starting site mapping on {args.target}...")
        found_urls = map_site(args.target, wordlist, extensions)
        if found_urls:
            print("Found URLs:")
            for url in found_urls:
                print(url)
        else:
            print("No URLs found.")
        sys.exit(0)

    if args.find_connected:
        interface = args.find_connected
        print(f"Discovering active hosts on {interface}...")
        hosts, error = get_active_hosts(interface)
        if error:
            print(f"Error: {error}")
        elif hosts:
            print("Active hosts:")
            for host in hosts:
                print(f"  IP: {host['ip']}, MAC: {host['mac']}")
        else:
            print("No active hosts found.")
        sys.exit(0)

    if args.internal:
        print("The following internal tools are available:")
        print("  - bruteforce: SSH bruteforcer (Go)")
        print("  - chat: Encrypted chat application (Go)")
        print("  - findConnected: Discover active hosts (Go)")
        print("  - portScanner: Port scanner (Go)")
        print("  - siteMapper: Site mapper (Go)")
        print("  - sniffer: Packet sniffer (Go and Python)")
        print("  - trojanCreator: Trojan creator (Go)")
        print("  - userRecon: User reconnaissance (Go)")
        print("\nTo use these tools, you need to compile and run them manually.")
        print("For Go programs, you need to have Go installed. You can then run them using 'go run <file>.go'.")
        print("For Python programs, you can run them using 'python <file>.py'.")
        print("Note: Some of these tools may require root privileges to run.")
        sys.exit(0)

    if args.user_recon:
        username = args.user_recon
        print(f"Searching for username '{username}' on social media...")
        found_urls = find_username(username)
        if found_urls:
            print("Found URLs:")
            for social, url in found_urls.items():
                print(f"  {social}: {url}")
        else:
            print("Username not found on any of the checked websites.")
        sys.exit(0)

    if not args.target:
        print("The --target argument is required when not using the web GUI.")
        sys.exit(1)

    if args.aggressive and not args.i_have_permission:
        print("Aggressive scans require the --i-have-permission flag.")
        sys.exit(1)

    target = args.target
    findings: List[Dict[str, Any]] = []

    # Add a progress bar
    total_scans = 5
    if args.deep:
        total_scans += 2
    with tqdm(total=total_scans) as pbar:
        pbar.set_description(f"Scanning {target}")

        # Connectivity check
        pbar.set_postfix_str("Connectivity Check")
        parsed_url = urlparse(target)
        host = parsed_url.hostname or target
        ip = get_host_ip(host)
        if not ip:
            add_finding(findings, "Host Unreachable", "Info", f"Could not resolve hostname: {host}")
            print_report(findings, args.output)
            return
        pbar.update(1)

        # Port scan
        pbar.set_postfix_str("Port Scan")
        ports_to_scan = [int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_PORTS
        open_ports = tcp_port_scan(ip, ports_to_scan, args.timeout)
        if open_ports:
            add_finding(findings, "Open Ports", "Info", f"Open ports found: {open_ports}")
        pbar.update(1)

        # Header check
        pbar.set_postfix_str("Header Check")
        check_security_headers(target, findings, args.timeout)
        pbar.update(1)

        # Version check
        pbar.set_postfix_str("Version Check")
        check_version(target, findings, args.timeout)
        pbar.update(1)

        # Deep scans
        if args.deep:
            pbar.set_postfix_str("Database Scan")
            check_databases(ip, findings, args.timeout)
            pbar.update(1)
            pbar.set_postfix_str("Admin Panel Scan")
            check_admin_panels(target, findings, args.timeout)
            pbar.update(1)

        # Aggressive checks
        if args.aggressive:
            pbar.set_postfix_str("SQLi Check")
            check_sqli(target, findings, args.timeout, args.aggressive)
            pbar.set_postfix_str("XSS Check")
            check_xss(target, findings, args.timeout, args.aggressive)
        pbar.update(1)

    print_report(findings, args.output)

if __name__ == "__main__":
    main()