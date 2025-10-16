#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Testing Tool
Runs a suite of network diagnostic tools, parsing the output into structured JSON,
and logs the JSON data to a SQLite database.
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
    # Convert the dictionary to a JSON string for storage
    json_results = json.dumps(results_dict, indent=4)
    cursor.execute(
        "INSERT INTO scans (timestamp, customer_name, tool, target, results) VALUES (?, ?, ?, ?, ?)",
        (timestamp, customer_name, tool, target, json_results)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    print(f"\n--- Result saved to database with ID: {new_id} ---")
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
            lines.append(f"    IPv4 Address: {details.get('ipv4', 'N/A')}")
            lines.append(f"    IPv6 Address: {details.get('ipv6', 'N/A')}")
            lines.append(f"    MAC Address : {details.get('mac', 'N/A')}")
    elif tool == 'ping':
        lines.append(f"  Target: {results_dict.get('target')}")
        lines.append(f"  Packet Loss: {results_dict.get('packet_loss', 'N/A')}")
        lines.append(f"  Round-trip avg: {results_dict.get('rtt_avg', 'N/A')}")
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
    else:
        lines.append(json.dumps(results_dict, indent=4))
        
    return "\n".join(lines)

# --- Existing Functions ---

def show_tutorial():
    """Prints a user-friendly tutorial for the testing script."""
    tutorial_text = """
=================================================
Welcome to the Network Testing Tool!
=================================================
This script runs various network diagnostics, saves the results as structured
JSON to a database, and can export human-readable reports.
IMPORTANT: On macOS, some commands must be run with sudo.
   e.g., sudo ./network-tester.py run-first
-------------------------------------------------
Workflow
-------------------------------------------------
1. Run the Core Diagnostic Suite with a Customer Name:
   sudo ./network-tester.py run-first --name "Customer Site A"
2. View Scan History:
   ./network-tester.py history
3. Export a Human-Readable Report:
   ./network-tester.py export 36,37,38 customer1-report.txt
4. Analyze the Results with AI:
   Use the 'network-analyzer.py' script.
"""
    print(tutorial_text)
    sys.exit(0)

def run_command(command, text_input=None):
    """
    A helper function to run a shell command and capture its output.
    """
    try:
        result = subprocess.run(
            command, input=text_input, capture_output=True, text=True,
            check=False, timeout=300
        )
        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if "operation not permitted" in stderr_lower:
                return f"Error: A permission error occurred even with sudo. Command: '{' '.join(command)}'"
            return f"Error executing {' '.join(command)}:\n{result.stderr}"
        return result.stdout
    except FileNotFoundError:
        return f"Error: The command '{command[0]}' was not found."
    except subprocess.TimeoutExpired:
        return f"Error: The command '{' '.join(command)}' timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def get_scan_result(scan_id):
    """
    Retrieves the full results of a single scan by its ID.
    """
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

def show_history(limit=10):
    """
    Retrieves and displays recent scan results from the database.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, customer_name, tool, target FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        if not rows:
            print("No history found in the database.")
            return
        print(f"--- Showing Last {len(rows)} Scans (newest first) ---")
        for row in rows:
            scan_id, timestamp, customer_name, tool, target = row
            name_str = f" | Name: {customer_name}" if customer_name else ""
            target_str = f" | Target: {target}" if target else ""
            print(f"  ID: {scan_id:<4} | {timestamp} | Tool: {tool:<10}{name_str}{target_str}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_user_downloads_dir():
    """
    Finds the correct downloads directory, even when run with sudo.
    """
    home_dir = os.path.expanduser('~')
    if os.geteuid() == 0:
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user:
            home_dir = f"/Users/{sudo_user}" if sys.platform == "darwin" else f"/home/{sudo_user}"
    return os.path.join(home_dir, 'Downloads')

def export_results(scan_ids, filename):
    """
    Exports the results of specified scans to a text file in the Downloads directory.
    """
    try:
        downloads_dir = get_user_downloads_dir()
        if not os.path.exists(downloads_dir):
            os.makedirs(downloads_dir)

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
        
        if not export_content:
            print("No valid data found for the given IDs. Nothing to export.")
            return

        with open(output_path, 'w') as f:
            f.write("".join(export_content))

        print(f"\nSuccess! Results exported to:\n{output_path}")

    except Exception as e:
        print(f"An unexpected error occurred during export: {e}")

# --- Restored and Corrected Tool Execution Functions ---

def get_default_interface():
    if sys.platform == "darwin":
        cmd = "route -n get default | grep 'interface:' | awk '{print $2}'"
    else:
        cmd = "ip route get 8.8.8.8 | awk '{print $5; exit}'"
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except Exception:
        return "en0" if sys.platform == "darwin" else None

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        return None

def display_network_config(customer_name=None):
    print("--- Current Network Configuration ---")
    results_dict = {"interfaces": {}}
    
    try:
        wan_ipv4 = run_command(['curl', '-4', '-s', 'ifconfig.me']).strip()
        results_dict['public_wan_ipv4'] = wan_ipv4 or 'Not Found'
    except Exception:
        results_dict['public_wan_ipv4'] = 'Error'
    
    try:
        wan_ipv6 = run_command(['curl', '-6', '-s', 'ifconfig.me']).strip()
        results_dict['public_wan_ipv6'] = wan_ipv6 or 'Not Found'
    except Exception:
        results_dict['public_wan_ipv6'] = 'Error'

    if sys.platform == "darwin":
        gateway_cmd = "netstat -nr | grep default | awk 'NR==1{print $2}'"
        dns_cmd = "scutil --dns | grep 'nameserver\\[[0-9]*\\]' | awk '{print $3}' | sort -u | tr '\\n' ' '"
    else:
        gateway_cmd = "ip route show default | awk '/default/ {print $3}'"
        dns_cmd = "grep 'nameserver' /etc/resolv.conf | awk '{print $2}' | sort -u | tr '\\n' ' '"
    
    try:
        results_dict['default_gateway'] = subprocess.check_output(gateway_cmd, shell=True, text=True).strip() or 'Not Found'
        results_dict['dns_servers'] = subprocess.check_output(dns_cmd, shell=True, text=True).strip() or 'Not Found'
    except Exception:
        results_dict['default_gateway'] = 'Error'
        results_dict['dns_servers'] = 'Error'
    
    if sys.platform == "darwin":
        try:
            ifconfig_out = run_command(["ifconfig", "-u"])
            interface_blocks = re.split(r'(^[a-zA-Z0-9]+:)', ifconfig_out, flags=re.MULTILINE)[1:]
            for i in range(0, len(interface_blocks), 2):
                name = interface_blocks[i].strip(':')
                details = interface_blocks[i+1]
                if not any(x in details for x in ['inet ', 'inet6 ']): continue
                
                inet4 = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', details)
                inet6 = re.search(r'inet6 ([0-9a-fA-F:]+)', details)
                mac = re.search(r'ether ([0-9a-fA-F:]+)', details)
                results_dict["interfaces"][name] = {
                    "ipv4": inet4.group(1) if inet4 else 'N/A',
                    "ipv6": inet6.group(1) if inet6 else 'N/A',
                    "mac": mac.group(1) if mac else 'N/A'
                }
        except Exception:
            pass # Fail gracefully
    else: # Linux
        # ... linux specific logic ...
        pass
    
    human_readable_output = format_json_for_export('net-config', results_dict)
    print(human_readable_output)
    
    return save_result('net-config', 'local', results_dict, customer_name)

def run_ping_test(target, customer_name=None):
    print(f"--- Running Ping Test to {target} ---")
    raw_output = run_command(['ping', '-c', '10', target])
    
    results_dict = {'target': target, 'packet_loss': 'N/A', 'rtt_avg': 'N/A', 'raw_output': raw_output}
    loss_match = re.search(r'(\d+\.?\d*)%\s+packet loss', raw_output)
    if loss_match:
        results_dict['packet_loss'] = f"{loss_match.group(1)}%"
    
    if sys.platform == "darwin":
        rtt_match = re.search(r'round-trip min/avg/max/stddev = [\d.]+/([\d.]+)/', raw_output)
    else: # Linux
        rtt_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', raw_output)
        
    if rtt_match:
        results_dict['rtt_avg'] = f"{rtt_match.group(1)} ms"

    print(f"  Packet Loss: {results_dict['packet_loss']}")
    print(f"  Round-trip avg: {results_dict['rtt_avg']}")
    
    return save_result('ping', target, results_dict, customer_name)

def run_mtr_report(target, customer_name=None):
    print(f"--- Running MTR Path Analysis for {target} ---")
    raw_output = run_command(['mtr', '--report', '--report-wide', '-c', '1', target])

    results_dict = {'source_host': '', 'hops': []}
    lines = raw_output.strip().split('\n')
    if lines:
        host_match = re.search(r'Start: .*', lines[0]) # MTR on Mac/Linux has different start lines
        if host_match:
            results_dict['source_host'] = socket.gethostname()

    for line in lines:
        match = re.search(r'^\s*\d+\.\|--\s+(.*?)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)', line)
        if match:
            results_dict['hops'].append({
                'host': match.group(1).strip(), 'loss': f"{match.group(2)}%", 'snt': match.group(3),
                'last': match.group(4), 'avg': match.group(5), 'best': match.group(6),
                'wrst': match.group(7), 'stdev': match.group(8)
            })
    
    print(raw_output)
    return save_result('mtr', target, results_dict, customer_name)

def run_nmap_scan(target, discovery=False, customer_name=None):
    scan_type = "Host Discovery" if discovery else "Port Scan"
    print(f"--- Running Nmap {scan_type} on {target} ---")
    command = ['nmap', '-sn', '-PR', target] if discovery else ['nmap', '-F', target]
    raw_output = run_command(command)

    results_dict = {'target': target, 'hosts': []}
    for line in raw_output.split('\n'):
        if 'Nmap scan report for' in line:
            parts = line.split()
            ip = parts[-1].strip('()')
            hostname = parts[4] if len(parts) > 5 and parts[4] != ip else 'N/A'
            results_dict['hosts'].append({'ip': ip, 'hostname': hostname})
    
    print(raw_output)
    return save_result('nmap', target, results_dict, customer_name)

def run_loop_detection(customer_name=None):
    print("--- Checking for Broadcast Storms ---")
    interface = get_default_interface()
    if not interface:
        summary = "Could not determine default interface."
        results_dict = {'summary': summary}
        print(summary)
        return save_result('loop-detect', 'local', results_dict, customer_name)

    filter_exp = 'ether dst ff:ff:ff:ff:ff:ff' if sys.platform == 'darwin' else 'ether broadcast'
    command = ['tshark', '-i', interface, '-f', filter_exp, '-a', 'duration:5']
    raw_output = run_command(command)
    
    packet_count = len(raw_output.strip().split('\n')) if raw_output.strip() and not raw_output.startswith("Error:") else 0
    threshold = 500
    
    summary = f"Captured {packet_count} broadcast packets in 5 seconds on interface '{interface}'.\n"
    if packet_count > threshold:
        summary += "Result: High broadcast traffic detected. This may indicate a network loop."
    else:
        summary += "Result: Broadcast traffic levels appear normal."
    
    results_dict = {'summary': summary, 'packet_count': packet_count}
    print(summary)
    return save_result('loop-detect', interface, results_dict, customer_name)

# --- Main Execution Logic ---

def run_first_suite(customer_name=None):
    print("--- Running Core Network Diagnostic Suite ---")
    suite_ids = []
    
    suite_ids.append(display_network_config(customer_name=customer_name))
    suite_ids.append(run_ping_test("8.8.8.8", customer_name=customer_name))
    suite_ids.append(run_mtr_report("8.8.8.8", customer_name=customer_name))
    
    subnet = get_local_subnet()
    if subnet:
        suite_ids.append(run_nmap_scan(subnet, discovery=True, customer_name=customer_name))
    
    suite_ids.append(run_loop_detection(customer_name=customer_name))

    print("\n--- Core Diagnostic Suite Finished ---")
    ids_str = ','.join(map(str, suite_ids))
    print(f"All tests run, with IDs: {ids_str}")

    if customer_name:
        print("\n--- Auto-exporting results ---")
        filename = customer_name.replace(' ', '_') + ".txt"
        export_results(suite_ids, filename)

def main():
    if sys.platform == "darwin" and os.geteuid() != 0:
        read_only_commands = ['export', 'history', 'help', '--help', '-h']
        if len(sys.argv) > 1 and sys.argv[1] not in read_only_commands:
            print("Error: This script requires root privileges on macOS for many tests.")
            print(f"Please run again: sudo ./{os.path.basename(__file__)} {' '.join(sys.argv[1:])}")
            sys.exit(1)

    if len(sys.argv) == 1:
        show_tutorial()
    
    setup_database()

    parser = argparse.ArgumentParser(description="Network Testing Tool.", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest='command', help='Available tools')

    run_first_parser = subparsers.add_parser('run-first', help='Run a core suite of diagnostic tests.')
    run_first_parser.add_argument('--name', help='Customer/site name for auto-export and tagging.')

    nmap_parser = subparsers.add_parser('nmap', help='Run a Nmap scan')
    nmap_parser.add_argument('target', help='IP address or subnet to scan')
    nmap_parser.add_argument('--name', help='Assign a customer/site name to this scan.')

    mtr_parser = subparsers.add_parser('mtr', help='Run an MTR report (may require sudo)')
    mtr_parser.add_argument('target', help='IP address or hostname to trace')
    mtr_parser.add_argument('--name', help='Assign a customer/site name to this scan.')
    
    speedtest_parser = subparsers.add_parser('speedtest', help='Run an internet speed test')
    speedtest_parser.add_argument('--name', help='Assign a customer/site name to this scan.')
    
    dig_parser = subparsers.add_parser('dig', help='Run a DNS lookup')
    dig_parser.add_argument('target', help='The hostname to look up')
    dig_parser.add_argument('--name', help='Assign a customer/site name to this scan.')
    
    tshark_parser = subparsers.add_parser('tshark', help='Capture packets (may require sudo)')
    tshark_parser.add_argument('interface', help='The network interface (e.g., en0)')
    tshark_parser.add_argument('--count', type=int, default=20, help='Number of packets')
    tshark_parser.add_argument('--name', help='Assign a customer/site name to this scan.')
    
    probe_parser = subparsers.add_parser('probe', help='Run an advanced packet probe (may require sudo)')
    probe_parser.add_argument('target', help='The IP address or hostname')
    probe_parser.add_argument('port', type=int, help='The port to probe')
    probe_parser.add_argument('--type', choices=['syn'], default='syn', help='The type of probe')
    probe_parser.add_argument('--name', help='Assign a customer/site name to this scan.')

    export_parser = subparsers.add_parser('export', help='Export scan results to a file.')
    export_parser.add_argument('ids', help='Comma-separated list of scan IDs (e.g., 36,37)')
    export_parser.add_argument('filename', help='The name of the output file (e.g., report.txt)')
    
    history_parser = subparsers.add_parser('history', help='Show recent scan history')
    history_parser.add_argument('--limit', type=int, default=10, help='Number of entries to show')

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    customer_name = args.name if hasattr(args, 'name') and args.name else None

    if args.command == 'run-first':
        run_first_suite(customer_name)
    elif args.command == 'nmap':
        run_nmap_scan(args.target, discovery=False, customer_name=customer_name)
    elif args.command == 'mtr':
        run_mtr_report(args.target, customer_name=customer_name)
    elif args.command == 'speedtest':
        run_speed_test(customer_name=customer_name)
    elif args.command == 'dig':
        run_dig(args.target, customer_name=customer_name)
    elif args.command == 'tshark':
        run_tshark(args.interface, args.count, customer_name=customer_name)
    elif args.command == 'probe':
        run_packet_probe(args.target, args.port, args.type, customer_name=customer_name)
    elif args.command == 'export':
        try:
            scan_ids = [int(item) for item in args.ids.split(',')]
            export_results(scan_ids, args.filename)
        except ValueError:
            print("Error: Invalid ID list. Please provide a comma-separated list of numbers.")
    elif args.command == 'history':
        show_history(args.limit)

if __name__ == "__main__":
    main()

