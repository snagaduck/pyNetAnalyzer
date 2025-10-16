#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Analyzer & Scanner
Runs individual diagnostic tools or a full suite, saves results as structured JSON
to a local SQLite database, and exports detailed, human-readable text reports.
"""

import subprocess
import argparse
import sys
import sqlite3
from datetime import datetime
import ipaddress
import socket
import re
import os
import json

# --- Database Configuration ---
DB_FILE = "scans.db"

def setup_database():
    """
    Sets up the SQLite database and creates the 'scans' table if it doesn't exist.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            customer_name TEXT,
            tool TEXT NOT NULL,
            target TEXT,
            results TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_result(tool, target, results_dict, customer_name=None):
    """
    Saves a scan result dictionary as a JSON string to the SQLite database.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    json_results = json.dumps(results_dict, indent=4)
    cursor.execute(
        "INSERT INTO scans (timestamp, customer_name, tool, target, results) VALUES (?, ?, ?, ?, ?)",
        (timestamp, customer_name, tool, target, json_results)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    print(f"--- Result for '{tool}' saved to database with ID: {new_id} ---")
    return new_id

# --- Data Formatting Functions ---

def format_json_for_export(tool, results_dict):
    """
    Takes a tool name and a results dictionary and returns a formatted human-readable string.
    """
    lines = []
    if tool == 'net-config':
        lines.append("--- Global Information ---")
        for key in ['public_wan_ipv4', 'public_wan_ipv6', 'default_gateway', 'dns_servers']:
            if key in results_dict:
                lines.append(f"  {key.replace('_', ' ').title():<20}: {results_dict[key]}")
        lines.append("\n--- Key Network Interfaces ---")
        for iface, details in results_dict.get('interfaces', {}).items():
            lines.append(f"\n  Interface: {iface}")
            lines.append(f"    {'IPv4 Address':<15}: {details.get('ipv4', 'N/A')}")
            lines.append(f"    {'IPv6 Address':<15}: {details.get('ipv6', 'N/A')}")
            lines.append(f"    {'MAC Address':<15}: {details.get('mac', 'N/A')}")
    elif tool == 'ping':
        lines.append(f"  {'Target':<20}: {results_dict.get('target', 'N/A')}")
        lines.append(f"  {'Packet Loss':<20}: {results_dict.get('packet_loss', 'N/A')}")
        lines.append(f"  {'Round-trip avg':<20}: {results_dict.get('rtt_avg', 'N/A')}")
        lines.append("\nRaw Output:\n" + results_dict.get('raw_output', ''))
    elif tool == 'mtr':
        lines.append("HOST: {:<40} Loss%   Snt   Last   Avg  Best  Wrst StDev".format(results_dict.get('source_host', '')))
        for i, hop in enumerate(results_dict.get('hops', []), 1):
            lines.append("{:>3}.|-- {:<40} {:>5} {:>5} {:>6} {:>5} {:>5} {:>5} {:>5}".format(
                i, hop.get('host', '???'), hop.get('loss', 'N/A'), hop.get('snt', 'N/A'),
                hop.get('last', 'N/A'), hop.get('avg', 'N/A'), hop.get('best', 'N/A'),
                hop.get('wrst', 'N/A'), hop.get('stdev', 'N/A')
            ))
    elif tool == 'nmap':
        lines.append(f"Scan Target: {results_dict.get('target')}")
        lines.append(f"Hosts Found: {len(results_dict.get('hosts', []))}")
        for host in results_dict.get('hosts', []):
            lines.append(f"  - Host: {host.get('ip')} ({host.get('hostname', 'N/A')}) is up")
    elif tool == 'loop-detect':
        lines.append(results_dict.get('summary', 'No summary available.'))
    elif tool == 'speedtest':
        lines.append(f"  {'Download':<20}: {results_dict.get('download_speed', 'N/A')}")
        lines.append(f"  {'Upload':<20}: {results_dict.get('upload_speed', 'N/A')}")
        lines.append(f"  {'Ping Latency':<20}: {results_dict.get('ping_latency', 'N/A')}")
        lines.append(f"  {'Server':<20}: {results_dict.get('server_name', 'N/A')}")
    elif tool == 'dig':
        lines.append(f"  {'Query':<20}: {results_dict.get('query', 'N/A')}")
        lines.append("  Answers:")
        for answer in results_dict.get('answers', []):
            lines.append(f"    - {answer}")
    elif tool == 'probe':
        lines.append(f"  {'Target':<20}: {results_dict.get('target', 'N/A')}")
        lines.append(f"  {'Port Status':<20}: {results_dict.get('status', 'N/A')}")
        lines.append("\nRaw Output:\n" + results_dict.get('raw', ''))
    else:
        lines.append(json.dumps(results_dict, indent=4))
        
    return "\n".join(lines)


# --- Helper Functions ---

def show_tutorial():
    """Prints a user-friendly tutorial for this script."""
    script_name = os.path.basename(__file__)
    tutorial_text = f"""
=================================================
Welcome to the Network Analyzer & Scanner!
=================================================
This script runs network diagnostics and saves the results.
IMPORTANT: Most commands must be run with sudo.

-------------------------------------------------
Primary Workflow
-------------------------------------------------
1. Run the Full Diagnostic Suite:
   This runs a series of tests and automatically exports a detailed report.
   sudo ./{script_name} suite --name "Customer Site A"

2. Run Individual Tools:
   You can also run any of the tools individually.
   sudo ./{script_name} speedtest --name "Customer A"
   sudo ./{script_name} mtr 8.8.8.8 --name "Customer B"
   sudo ./{script_name} probe 192.168.1.1 443 --name "Router SSL Check"

3. View Scan History & Export:
   ./{script_name} history
   ./{script_name} export 1,2,3 report.txt

4. Analyze with AI:
   Use the 'network-ai-diagnostics.py' script with Scan IDs.
"""
    print(tutorial_text)
    sys.exit(0)

def run_command(command):
    """
    A helper function to run a shell command and capture its output.
    Returns a tuple: (stdout, stderr).
    """
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=300
        )
        # Return stdout and stderr separately
        return result.stdout, result.stderr
    except FileNotFoundError:
        return None, f"Error: The command '{command[0]}' was not found."
    except subprocess.TimeoutExpired:
        return None, f"Error: The command '{' '.join(command)}' timed out."
    except Exception as e:
        return None, f"An unexpected error occurred: {e}"

def get_scan_result(scan_id):
    """Retrieves the full results of a single scan by its ID."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT tool, target, results, timestamp, customer_name FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        return row
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def show_history(limit=15):
    """Retrieves and displays recent scan results from the database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, customer_name, tool, target FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        if not rows: print("No history found in the database."); return
        print(f"--- Showing Last {len(rows)} Scans (newest first) ---")
        for row in rows:
            scan_id, timestamp, customer_name, tool, target = row
            name_str = f" | Name: {customer_name}" if customer_name else ""
            target_str = f" | Target: {target}" if target else ""
            print(f"  ID: {scan_id:<4} | {timestamp} | Tool: {tool:<12}{name_str}{target_str}")
    except sqlite3.Error as e: print(f"Database error: {e}")

def get_user_downloads_dir():
    """Finds the correct downloads directory, even when run with sudo."""
    home_dir = os.path.expanduser('~')
    if os.geteuid() == 0:
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user: home_dir = f"/Users/{sudo_user}" if sys.platform == "darwin" else f"/home/{sudo_user}"
    return os.path.join(home_dir, 'Downloads')

def export_results(scan_ids, filename):
    """Exports the results of specified scans to a text file in the Downloads directory."""
    try:
        downloads_dir = get_user_downloads_dir()
        if not os.path.exists(downloads_dir): os.makedirs(downloads_dir)
        output_path = os.path.join(downloads_dir, filename)
        
        export_content = []
        print(f"--- Exporting results for Scan IDs: {', '.join(map(str, scan_ids))} ---")

        for scan_id in scan_ids:
            scan_data = get_scan_result(scan_id)
            if scan_data:
                tool, target, json_results, timestamp, customer_name = scan_data
                name_str = f" | NAME: {customer_name}" if customer_name else ""
                header = f"==================== SCAN ID: {scan_id} | {timestamp} | TOOL: {tool}{name_str} ====================\n"
                export_content.append(header)
                
                results_dict = json.loads(json_results)
                human_readable_results = format_json_for_export(tool, results_dict)
                export_content.append(human_readable_results)
                export_content.append("\n\n")
            else:
                print(f"Warning: Could not find data for Scan ID {scan_id}. Skipping.")
        
        if not export_content: print("No valid data found for the given IDs. Nothing to export."); return

        with open(output_path, 'w') as f: f.write("".join(export_content))
        print(f"\nSuccess! Results exported to:\n{output_path}")

    except Exception as e: print(f"An unexpected error occurred during export: {e}")

# --- Tool Execution Functions ---

def get_network_config(customer_name=None, verbose=False):
    print("--- Getting Network Configuration ---")
    results = {'interfaces': {}}
    
    stdout, stderr = run_command(['curl', '-4', '-s', 'ifconfig.me'])
    results['public_wan_ipv4'] = stdout.strip() if stdout else f"Not Found ({stderr or 'No error message'})"
    
    stdout, stderr = run_command(['curl', '-6', '-s', 'ifconfig.me'])
    results['public_wan_ipv6'] = stdout.strip() if stdout else "Not Found"

    gateway_cmd = "netstat -nr | grep default | awk 'NR==1{print $2}'" if sys.platform == "darwin" else "ip route show default | awk '/default/ {print $3}'"
    stdout, _ = run_command(['sh', '-c', gateway_cmd])
    results['default_gateway'] = stdout.strip() or 'Not Found'

    dns_cmd = "scutil --dns | grep 'nameserver\\[[0-9]*\\]' | awk '{print $3}'" if sys.platform == "darwin" else "grep 'nameserver' /etc/resolv.conf | awk '{print $2}'"
    stdout, _ = run_command(['sh', '-c', dns_cmd])
    dns_list = stdout.split()
    results['dns_servers'] = ' '.join(list(dict.fromkeys(dns_list))) or 'Not Found'

    if sys.platform == "darwin":
        try:
            ignored_prefixes = ('awdl', 'llw')
            stdout, stderr = run_command(["ifconfig", "-u"])
            if stderr: raise Exception(stderr) # If command fails, raise exception
            
            interface_blocks = re.split(r'(^[a-zA-Z0-9]+:)', stdout, flags=re.MULTILINE)[1:]
            for i in range(0, len(interface_blocks), 2):
                name = interface_blocks[i].strip(':')
                if name.startswith(ignored_prefixes): continue
                
                details = interface_blocks[i+1]
                if not any(x in details for x in ['inet ', 'inet6 ']): continue
                
                inet4 = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', details)
                inet6 = re.search(r'inet6 ([0-9a-fA-F:]+)', details)
                mac = re.search(r'ether ([0-9a-fA-F:]+)', details)
                results["interfaces"][name] = {
                    "ipv4": inet4.group(1) if inet4 else 'N/A',
                    "ipv6": inet6.group(1).split('%')[0] if inet6 else 'N/A',
                    "mac": mac.group(1) if mac else 'N/A'
                }
        except Exception as e:
            print(f"  Could not parse interface details: {e}")

    human_readable_output = format_json_for_export('net-config', results)
    print(human_readable_output)
    return save_result('net-config', 'local', results, customer_name)

def run_ping_test(target, customer_name=None, verbose=False):
    print(f"--- Running Ping Test to {target} ---")
    stdout, stderr = run_command(['ping', '-c', '10', target])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)

    results = {'target': target, 'packet_loss': 'N/A', 'rtt_avg': 'N/A', 'raw_output': raw_output}
    loss_match = re.search(r'(\d+\.?\d*)\% packet loss', raw_output)
    if loss_match: results['packet_loss'] = f"{loss_match.group(1)}%"

    rtt_match = re.search(r'min/avg/max/.+dev = [\d.]+/([\d.]+)/', raw_output)
    if rtt_match: results['rtt_avg'] = f"{rtt_match.group(1)} ms"

    print(f"  Packet Loss: {results['packet_loss']}\n  Round-trip avg: {results['rtt_avg']}")
    return save_result('ping', target, results, customer_name)

def run_mtr_report(target, customer_name=None, verbose=False):
    print(f"--- Running MTR Path Analysis for {target} ---")
    stdout, stderr = run_command(['mtr', '--report', '--report-wide', '-c', '1', target])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)

    results = {'source_host': socket.gethostname(), 'hops': []}
    for line in raw_output.strip().split('\n'):
        match = re.search(r'^\s*\d+\.\|--\s+(.*?)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)', line)
        if match:
            results['hops'].append({
                'host': match.group(1).strip(), 'loss': f"{match.group(2)}%", 'snt': match.group(3),
                'last': match.group(4), 'avg': match.group(5), 'best': match.group(6),
                'wrst': match.group(7), 'stdev': match.group(8)
            })
    print(format_json_for_export('mtr', results))
    return save_result('mtr', target, results, customer_name)

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); 
        local_ip = s.getsockname()[0]; s.close()
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception: return None

def run_nmap_scan(target, customer_name=None, verbose=False):
    print(f"--- Running Nmap Host Discovery on {target} ---")
    stdout, stderr = run_command(['nmap', '-sn', target])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)
    
    results = {'target': target, 'hosts': []}
    for block in raw_output.split('Nmap scan report for '):
        if not block.strip(): continue
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', block)
        ip = ip_match.group(1) if ip_match else 'N/A'
        hostname_match = re.search(r'^(.*?)\s+\(', block)
        hostname = hostname_match.group(1) if hostname_match and hostname_match.group(1) != ip else 'N/A'
        results['hosts'].append({'ip': ip, 'hostname': hostname})
        
    # Print the formatted output to the console
    print(format_json_for_export('nmap', results))
    return save_result('nmap', target, results, customer_name)

def run_loop_detection(customer_name=None, verbose=False):
    print("--- Checking for Broadcast Storms ---")
    default_iface_cmd = "route -n get default | grep 'interface:' | awk '{print $2}'" if sys.platform == "darwin" else "ip route get 8.8.8.8 | awk '{print $5; exit}'"
    interface, _ = run_command(['sh', '-c', default_iface_cmd])
    interface = interface.strip()
    if not interface:
        summary = "Could not determine default interface for loop detection."
        print(summary); return save_result('loop-detect', 'local', {'summary': summary}, customer_name)
    
    filter_exp = 'ether dst ff:ff:ff:ff:ff:ff'
    command = ['tshark', '-i', interface, '-f', filter_exp, '-a', 'duration:5']
    stdout, stderr = run_command(command)
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)

    packet_count = len(raw_output.strip().split('\n')) if stdout.strip() else 0
    threshold = 500
    
    summary = f"Captured {packet_count} broadcast packets in 5 seconds on interface '{interface}'.\n"
    summary += "Result: High broadcast traffic detected." if packet_count > threshold else "Result: Broadcast traffic levels appear normal."
    
    results = {'summary': summary, 'packet_count': packet_count}
    print(summary)
    return save_result('loop-detect', interface, results, customer_name)

def run_speed_test(customer_name=None, verbose=False):
    print("--- Running Internet Speed Test ---")
    stdout, stderr = run_command(['speedtest-cli', '--json'])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)
    results = {}
    try:
        data = json.loads(stdout)
        results = {
            'download_speed': f"{data['download'] / 1_000_000:.2f} Mbps",
            'upload_speed': f"{data['upload'] / 1_000_000:.2f} Mbps",
            'ping_latency': f"{data['ping']} ms",
            'server_name': data['server']['name']
        }
        print(f"  Download: {results['download_speed']}\n  Upload: {results['upload_speed']}")
    except (json.JSONDecodeError, KeyError, TypeError):
        print(f"  Error: Could not parse speedtest-cli output. {stderr}")
        results = {'error': raw_output}
    return save_result('speedtest', 'internet', results, customer_name)

def run_dig(target, customer_name=None, verbose=False):
    print(f"--- Running DNS Lookup for {target} ---")
    stdout, stderr = run_command(['dig', target])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)
    results = {'query': target, 'answers': []}
    answer_section = re.search(r'ANSWER SECTION:\n(.*?)\n\n', raw_output, re.DOTALL)
    if answer_section:
        results['answers'] = [line for line in answer_section.group(1).split('\n') if not line.startswith(';')]
    print("  Answers Found:", len(results['answers']))
    return save_result('dig', target, results, customer_name)

def run_tshark(interface, count, customer_name=None, verbose=False):
    print(f"--- Capturing {count} packets on {interface} with TShark ---")
    stdout, stderr = run_command(['tshark', '-i', interface, '-c', str(count)])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)
    packet_count = len(stdout.strip().split('\n')) if stdout.strip() else 0
    results = {'interface': interface, 'packets_captured': packet_count, 'raw': raw_output}
    print(f"  Captured {packet_count} packets.")
    return save_result('tshark', interface, results, customer_name)

def run_packet_probe(target, port, customer_name=None, verbose=False):
    print(f"--- Running Nmap SYN Probe on {target}:{port} ---")
    stdout, stderr = run_command(['nmap', '-sS', '-p', str(port), target])
    raw_output = stdout if stdout else stderr
    if verbose: print(raw_output)
    results = {'target': f"{target}:{port}", 'status': 'N/A', 'raw': raw_output}
    status_match = re.search(rf'{port}/tcp\s+(\w+)', raw_output)
    if status_match: results['status'] = status_match.group(1)
    print(f"  Port Status: {results['status']}")
    return save_result('probe', f"{target}:{port}", results, customer_name)

# --- Main Execution Logic ---

def run_suite(customer_name, verbose):
    print("\n--- Running Core Network Diagnostic Suite ---")
    if not customer_name:
        try:
            customer_name = input("Enter a customer/site name for this scan suite: ")
            if not customer_name: print("Customer name cannot be empty. Exiting."); sys.exit(1)
        except (EOFError, KeyboardInterrupt): print("\nScan cancelled."); sys.exit(0)
    
    suite_ids = []
    suite_ids.append(get_network_config(customer_name, verbose))
    suite_ids.append(run_ping_test("8.8.8.8", customer_name, verbose))
    suite_ids.append(run_mtr_report("8.8.8.8", customer_name, verbose))
    subnet = get_local_subnet()
    if subnet: suite_ids.append(run_nmap_scan(subnet, customer_name, verbose))
    suite_ids.append(run_loop_detection(customer_name, verbose))
    
    print("\n--- Core Diagnostic Suite Finished ---")
    ids_str = ','.join(map(str, filter(None, suite_ids)))
    print(f"All tests run, with IDs: {ids_str}")

    print("\n--- Auto-exporting results ---")
    filename = customer_name.replace(' ', '_').replace('/', '_') + "_suite_report.txt"
    export_results(suite_ids, filename)

def main():
    if len(sys.argv) == 1: show_tutorial(); return
    setup_database()

    parser = argparse.ArgumentParser(description="Network Analyzer & Scanner.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--name', help='Customer/site name for tagging the scan.')
    parent_parser.add_argument('--verbose', action='store_true', help='Enable detailed raw output.')

    subparsers.add_parser('suite', help='Run the full diagnostic suite.', parents=[parent_parser])
    history_parser = subparsers.add_parser('history', help='Show recent scan history.')
    history_parser.add_argument('--limit', type=int, default=15, help='Number of entries to show.')
    export_parser = subparsers.add_parser('export', help='Export scan results to a file.')
    export_parser.add_argument('ids', help='Comma-separated list of scan IDs (e.g., 1,2,3).')
    export_parser.add_argument('filename', help='Output filename (e.g., report.txt).')
    
    mtr_parser = subparsers.add_parser('mtr', help='Run an MTR report.', parents=[parent_parser])
    mtr_parser.add_argument('target', help='The hostname or IP to trace.')
    
    speedtest_parser = subparsers.add_parser('speedtest', help='Run an internet speed test.', parents=[parent_parser])
    
    dig_parser = subparsers.add_parser('dig', help='Run a DNS lookup.', parents=[parent_parser])
    dig_parser.add_argument('target', help='The hostname to look up.')
    
    tshark_parser = subparsers.add_parser('tshark', help='Capture packets.', parents=[parent_parser])
    tshark_parser.add_argument('interface', help='The network interface (e.g., en0).')
    tshark_parser.add_argument('--count', type=int, default=20, help='Number of packets to capture.')
    
    probe_parser = subparsers.add_parser('probe', help='Run an Nmap SYN probe on a port.', parents=[parent_parser])
    probe_parser.add_argument('target', help='The IP address or hostname to probe.')
    probe_parser.add_argument('port', type=int, help='The port number to probe.')

    args = parser.parse_args()
    
    if args.command in ['suite', 'mtr', 'tshark', 'probe'] and os.geteuid() != 0:
        print(f"\nError: The '{args.command}' command requires sudo."); sys.exit(1)

    customer_name = args.name if hasattr(args, 'name') else None
    verbose = args.verbose if hasattr(args, 'verbose') else False

    if args.command == 'suite': run_suite(customer_name, verbose)
    elif args.command == 'history': show_history(args.limit)
    elif args.command == 'export':
        try:
            scan_ids = [int(item) for item in args.ids.split(',')]
            export_results(scan_ids, args.filename)
        except ValueError: print("Error: Invalid ID list. Must be comma-separated numbers.")
    elif args.command == 'mtr': run_mtr_report(args.target, customer_name, verbose)
    elif args.command == 'speedtest': run_speed_test(customer_name, verbose)
    elif args.command == 'dig': run_dig(args.target, customer_name, verbose)
    elif args.command == 'tshark': run_tshark(args.interface, args.count, customer_name, verbose)
    elif args.command == 'probe': run_packet_probe(args.target, args.port, customer_name, verbose)
    else: parser.print_help()

if __name__ == "__main__":
    main()

