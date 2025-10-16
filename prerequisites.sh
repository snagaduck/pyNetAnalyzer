#!/bin/bash

# pyNetAnalyzer-prerequisites.sh
# An interactive setup script to ensure all dependencies for the pyNetAnalyzer toolkit are installed.

# --- Helper Functions ---

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to ask the user for confirmation
ask_to_install() {
    read -p "-> '$1' is missing. This is required to run all tests. Install it now? (y/n) " -n 1 -r
    echo # Move to a new line
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping installation of '$1'. Some script features may not work."
        return 1
    fi
    return 0
}

echo "=========================================="
echo "pyNetAnalyzer Prerequisite Checker"
echo "=========================================="
echo "This script will check for and offer to install missing dependencies."
echo

# --- OS Specific Logic ---

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS Logic
    echo "Detected macOS. Checking for Homebrew and required packages..."
    echo

    # Check for Homebrew
    if ! command_exists brew; then
        read -p "-> Homebrew is not installed. It is required to install other tools. Install Homebrew now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Installing Homebrew... This may take a few minutes and might ask for your password."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            
            # Add Homebrew to PATH for M1/M2/M3 Macs
            if [[ -x "/opt/homebrew/bin/brew" ]]; then
                 echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
                 eval "$(/opt/homebrew/bin/brew shellenv)"
                 echo "Homebrew path added to your shell configuration."
            fi
        else
            echo "Homebrew is required. Aborting setup."
            exit 1
        fi
    else
        echo "-> Homebrew is already installed. ✓"
    fi
    
    # List of required packages for macOS
    packages=("nmap" "mtr" "speedtest-cli" "wireshark" "bind")

    for pkg in "${packages[@]}"; do
        # 'wireshark' installs 'tshark', 'bind' installs 'dig'
        tool_to_check=$pkg
        if [[ "$pkg" == "wireshark" ]]; then
            tool_to_check="tshark"
        elif [[ "$pkg" == "bind" ]]; then
            tool_to_check="dig"
        fi

        if ! command_exists "$tool_to_check"; then
            if ask_to_install "$pkg"; then
                echo "Installing '$pkg' with Homebrew..."
                brew install "$pkg"
            fi
        else
            echo "-> '$pkg' is already installed. ✓"
        fi
    done

elif [[ -f /etc/debian_version ]]; then
    # Debian/Ubuntu Linux Logic
    echo "Detected Debian/Ubuntu Linux. Checking for required packages..."
    echo

    # List of required packages for Debian/Ubuntu
    packages=("nmap" "mtr-tiny" "speedtest-cli" "tshark" "hping3" "dnsutils" "arp-scan")

    for pkg in "${packages[@]}"; do
        # Check if the package is installed
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            if ask_to_install "$pkg"; then
                echo "Installing '$pkg' with apt... This may require your password."
                sudo apt update && sudo apt install -y "$pkg"
            fi
        else
            echo "-> '$pkg' is already installed. ✓"
        fi
    done

else
    echo "Unsupported operating system. This script only supports macOS and Debian-based Linux."
    exit 1
fi

# --- Ollama Check (Platform Agnostic) ---
echo
echo "--- Checking for Ollama ---"
if ! command_exists ollama; then
    echo "-> Ollama is not installed."
    echo "   This is NOT required to run the network analyzer script."
    echo "   This is required to run the AI analysis script."
    echo "   Please install it manually from https://ollama.com"
    echo "   (Download the app for macOS, or run the curl script for Linux)."
else
    echo "-> Ollama is already installed. ✓"
    echo "   Don't forget to pull the models you want to test, for example:"
    echo "   ollama pull gemma2:9b"
fi

echo
echo "=========================================="
echo "Prerequisite check finished!"
echo "=========================================="
