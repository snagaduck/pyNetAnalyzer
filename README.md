pyNetAnalyzer

An AI-Powered Network Diagnostic Toolkit for macOS and Linux.

pyNetAnalyzer is a command-line toolkit designed for network technicians and enthusiasts to run a comprehensive suite of network diagnostics, log the results to a local database, and perform intelligent analysis using local Large Language Models (LLMs) via Ollama.

Core Features

Comprehensive Testing Suite: Runs essential network tools like ping, nmap (ARP scan), mtr, tshark (for loop detection), dig, and more.

Structured Data Storage: All test results are parsed and saved as structured JSON in a local SQLite database (scans.db), separating data from presentation.

Cross-Platform Compatibility: Works on Debian-based Linux (like Raspberry Pi OS) and macOS, with platform-specific commands handled automatically.

Human-Readable Reports: Export raw results from multiple tests into a clean, consolidated text file perfect for reports or sharing.

AI-Powered Analysis: Use the analyzer script to perform benchmarks across multiple local LLMs (Gemma, GPT-OSS, Phi, etc.) to get an AI-driven summary of network health.

Modular Architecture: The project is split into two focused scripts: one for testing, one for analysis.

Project Structure

This toolkit consists of two main scripts:

network-tester.py: The data-gathering engine. Its job is to run the network tests, parse the output into JSON, and save everything to the scans.db database. It also handles exporting human-readable reports.

network-analyzer.py: The AI analysis and benchmarking engine. It reads the structured data from the database and uses Ollama to perform analysis with various large language models.

Prerequisites

Python 3.8+

Ollama installed and running.

On macOS: Homebrew package manager.

On Linux: apt package manager.

Installation

Clone the repository:

git clone [https://github.com/snagaduck/pyNetAnalyzer.git](https://github.com/snagaduck/pyNetAnalyzer.git)
cd pyNetAnalyzer


Install Network Tools:

On macOS (using Homebrew):

brew install nmap mtr speedtest-cli wireshark bind


On Debian/Ubuntu Linux:

sudo apt update && sudo apt install nmap mtr speedtest-cli tshark hping3 dnsutils arp-scan -y


Download AI Models with Ollama:
Pull the models you want to use for analysis. The analyzer script is pre-configured to benchmark several popular models.

ollama pull gemma2:9b
ollama pull gemma3:12b
ollama pull gpt-oss:20b
ollama pull phi3


Usage Guide

1. Run Diagnostic Tests (network-tester.py)

The first step is always to run tests to gather data. On macOS, many tests require root privileges.

Run the core diagnostic suite and tag it with a customer name:
This will run a battery of tests and automatically export a report to your Downloads folder.

sudo ./network-tester.py run-first --name "Customer Site A"


Run an individual scan:
You can also run single tests and tag them.

sudo ./network-tester.py nmap 192.168.1.0/24 --name "Local Network Scan"


View your scan history:
This command does not require sudo.

./network-tester.py history


Manually export results:
Combine the results from specific scan IDs into a single text file.

./network-tester.py export 45,46,47,48,49 client-report.txt


2. Analyze Results (network-analyzer.py)

After gathering data, use the analyzer to get AI-powered insights.

Run a benchmark across all configured models:
This will take the results from the specified scan IDs and have each LLM provide its analysis and performance metrics.

./network-analyzer.py benchmark 45,46,47,48,49 "Summarize the health of this network and point out any potential issues."


License

This project is licensed under the MIT License. See the LICENSE file for details.
