#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Analysis Tool
Retrieves test results from a SQLite database and uses large language models
to perform analysis. Includes a benchmark feature to compare models.
"""

import subprocess
import argparse
import sys
import sqlite3
import re
import json

# --- Configuration ---
DB_FILE = "scans.db"

def run_command(command, text_input=None):
    """
    A helper function to run a shell command and capture its output.
    Captures both stdout and stderr.
    """
    try:
        result = subprocess.run(
            command, input=text_input, capture_output=True, text=True,
            check=False, timeout=1800 # 30 minute timeout for large models
        )
        if result.returncode != 0:
            return f"Error executing {' '.join(command)}:\n{result.stderr}", ""
        return result.stdout, result.stderr
    except FileNotFoundError:
        return f"Error: The command '{command[0]}' was not found. Is Ollama installed and in your PATH?", ""
    except subprocess.TimeoutExpired:
        return f"Error: The command '{' '.join(command)}' timed out after 30 minutes.", ""
    except Exception as e:
        return f"An unexpected error occurred: {e}", ""

# --- Database Functions ---

def get_scan_result(scan_id):
    """
    Retrieves the full results of a single scan by its ID.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT tool, target, results, customer_name FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        return row
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def get_last_scan_ids(limit=5):
    """
    Gets the IDs of the most recent scans from the database.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [row[0] for row in rows]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

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

# --- AI and Analysis Functions ---

def get_installed_models():
    """
    Runs 'ollama list' and parses the output to get a list of model names.
    """
    stdout, stderr = run_command(['ollama', 'list'])
    if "Error" in stdout:
        print("Could not get model list. Is the Ollama application running?")
        return []
    
    lines = stdout.strip().split('\n')
    # The first line is the header, so we skip it
    models = [line.split()[0] for line in lines[1:]]
    return models

def parse_ollama_stats(stderr_output):
    """
    Parses the verbose output from Ollama's stderr to extract performance metrics.
    """
    metrics = { "Total Duration": "N/A", "Prompt Eval Speed": "N/A", "Generation Speed": "N/A" }
    for line in stderr_output.split('\n'):
        if 'total duration' in line:
            metrics["Total Duration"] = line.split(':')[-1].strip()
        if 'prompt eval rate' in line:
            metrics["Prompt Eval Speed"] = line.split(':')[-1].strip()
        if 'eval rate' in line and 'prompt' not in line:
            metrics["Generation Speed"] = line.split(':')[-1].strip()
    return (
        f"  - Total Duration   : {metrics['Total Duration']}\n"
        f"  - Prompt Eval Speed: {metrics['Prompt Eval Speed']}\n"
        f"  - Generation Speed : {metrics['Generation Speed']}"
    )

def perform_analysis(scan_ids, prompt, model_name):
    """
    The core analysis function that takes scan IDs, a prompt, and a model name,
    then returns the analysis and performance stats.
    """
    full_context = "CONTEXT (in JSON format):\n"
    for scan_id in scan_ids:
        scan_data = get_scan_result(scan_id)
        if scan_data:
            tool, target, json_results, customer_name = scan_data
            name_str = f" (Name: {customer_name})" if customer_name else ""
            full_context += f"--- Scan ID {scan_id} (Tool: {tool}{name_str}, Target: {target or 'N/A'}) ---\n"
            full_context += json_results.strip() + "\n"
            full_context += f"--- End of Scan ID {scan_id} ---\n\n"
        else:
            print(f"Warning: Could not find data for Scan ID {scan_id}. Skipping.")

    if full_context == "CONTEXT (in JSON format):\n":
        return "Error: No valid data found for the given IDs.", ""

    system_prompt = """
You are a network diagnostics bot. Your job is to analyze the technical data, provided as a series of JSON objects, and create a summary for a network technician.

**ANALYSIS CHECKLIST:**
1.  **Ping/MTR:** Check for 'packet_loss' (must be "0.0%"). Check for high 'rtt_avg' or 'avg' latency in hops.
2.  **Nmap:** Look for unexpected devices in the 'hosts' list.
3.  **Net-Config:** Verify 'public_wan_ipv4' exists. Check for multiple active interfaces.
4.  **Loop Detection:** Check 'packet_count' from the loop-detect tool. A high number (>500) is a strong indicator of a network loop.

**RESPONSE FORMATTING:**
1.  Start with a single sentence summarizing the overall network health.
2.  Use a bulleted list for specific findings.
3.  Prefix each finding with either "* Issue:" or "* Observation:".
4.  BE CONCISE and base your analysis ONLY on the provided JSON data.
"""
    
    final_prompt = f"{system_prompt}\n{full_context}\nBased on the JSON data, provide a summary addressing the user's question: '{prompt}'"
    
    analysis, stats = run_command(['ollama', 'run', '--verbose', model_name], text_input=final_prompt)
    return analysis, stats

def run_benchmark():
    """
    Automatically finds installed models and benchmarks them against the last 5 scans.
    """
    print("--- Starting AI Analysis Benchmark ---")
    
    # 1. Get installed models
    installed_models = get_installed_models()
    if not installed_models:
        print("No Ollama models found. Please pull a model first (e.g., 'ollama pull gemma2:9b').")
        return

    # 2. Get last 5 scan IDs
    scan_ids = get_last_scan_ids(5)
    if not scan_ids:
        print("No scans found in the database. Please run 'network-tester.py' first.")
        return
        
    print(f"Found {len(installed_models)} models to test against the last {len(scan_ids)} scans (IDs: {', '.join(map(str, scan_ids))}).")
    
    # 3. Loop through and run benchmark
    fixed_prompt = "Can you determine any issues within this network?"
    for model in installed_models:
        print("\n" + "="*50)
        print(f"--- BENCHMARKING MODEL: {model} ---")
        print("="*50)
        print("Running analysis... this may take some time.")

        analysis, stats = perform_analysis(scan_ids, fixed_prompt, model)
        
        print("\n--- MODEL'S ANALYSIS ---")
        print(analysis.strip())
        
        print("\n--- PERFORMANCE METRICS ---")
        print(parse_ollama_stats(stats))

    print("\n" + "="*50)
    print("--- Benchmark Finished ---")
    print("="*50)

def print_model_help_and_exit():
    """
    Runs 'ollama list' and prints a helpful error message, then exits.
    """
    print("Error: --model flag is required for the 'analyze' command.")
    print("-" * 20)
    print("Please choose from one of your installed models below:")
    
    installed_models = get_installed_models()
    if installed_models:
        print("\nAvailable Models:")
        # Re-run ollama list just to get the nicely formatted table
        list_output, _ = run_command(['ollama', 'list'])
        print(list_output)
    else:
        print("\nYou have no models installed.")

    print("To download a new model, use: ollama pull <model_name>")
    print("Example: ollama pull gemma2:9b")
    print("\nExample Usage:")
    print("./network-analyzer.py analyze 1,2,3 --model gemma2:9b \"Are there any issues?\"")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Network Analysis Tool with AI benchmarking.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    history_parser = subparsers.add_parser('history', help='Show recent scan history')
    history_parser.add_argument('--limit', type=int, default=10, help='Number of entries to show')
    
    view_parser = subparsers.add_parser('view', help='View the full results of a specific scan')
    view_parser.add_argument('id', type=int, help='The ID of the scan to view (outputs raw JSON)')

    # New benchmark command - no arguments needed
    subparsers.add_parser('benchmark', help='Benchmark all local models against the last 5 scans.')

    # New analyze command - requires --model
    analyze_parser = subparsers.add_parser('analyze', help='Run a focused analysis with a specific model.')
    analyze_parser.add_argument('ids', help='Comma-separated list of scan IDs (e.g., 34,35,36)')
    analyze_parser.add_argument('prompt', help='The question to ask the model.')
    analyze_parser.add_argument('--model', help='The name of the Ollama model to use (e.g., gemma2:9b)')

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == 'history':
        show_history(args.limit)
    elif args.command == 'view':
        scan_data = get_scan_result(args.id)
        if scan_data:
            print(scan_data[2]) 
        else:
            print(f"Error: No scan found with ID {args.id}")
    elif args.command == 'benchmark':
        run_benchmark()
    elif args.command == 'analyze':
        if not args.model:
            print_model_help_and_exit()
        try:
            scan_ids = [int(item) for item in args.ids.split(',')]
            print(f"--- Running Analysis with Model: {args.model} ---")
            analysis, stats = perform_analysis(scan_ids, args.prompt, args.model)
            print("\n--- MODEL'S ANALYSIS ---")
            print(analysis.strip())
            print("\n--- PERFORMANCE METRICS ---")
            print(parse_ollama_stats(stats))
        except ValueError:
            print("Error: Invalid ID list. Please provide a comma-separated list of numbers (e.g., 34,35,36).")

if __name__ == "__main__":
    main()

