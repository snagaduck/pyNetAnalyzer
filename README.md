# pyNetAnalyzer

> A powerful and lightweight Python tool for network diagnostics and analysis. `pyNetAnalyzer` provides a simple CLI interface to run a suite of tests and gather critical network information.

## Features

* **Automated Diagnostics:** Run a comprehensive suite of network tests with a single command.
* **Clear Results:** Get easy-to-read output for latency, DNS, and gateway checks.
* **Lightweight & Fast:** Built with standard Python libraries for maximum compatibility and speed.
* **Extensible:** Designed to be easily extended with new diagnostic modules.

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine.

### Prerequisites

* Python 3.9+
* `pip` for installing packages

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/snagaduck/pyNetAnalyzer.git](https://github.com/snagaduck/pyNetAnalyzer.git)
    ```

2.  **Navigate to the project directory:**
    ```bash
    cd pyNetAnalyzer
    ```

3.  **Install dependencies:**
    The project has minimal dependencies, but you can install them from `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The primary way to use `pyNetAnalyzer` is through its command-line interface.

**Basic Example:**
To run the default diagnostic suite, execute the main script with `sudo` permissions:

```bash
sudo python3 pyNetAnalyzer.py
```

**Running with Arguments:**
You can specify arguments to customize the tests.

```bash
# Run tests for a specific customer and enable verbose output
sudo python3 pyNetAnalyzer.py --name "ExampleCorp" --verbose
```

### Command-Line Arguments

| Argument    | Type   | Default | Description                               |
| :---------- | :----- | :------ | :---------------------------------------- |
| `--name`    | string | `None`  | A name/identifier for the test run.       |
| `--export`  | flag   | `False` | Export test results to a `.log` file.     |
| `--verbose` | flag   | `False` | Enable detailed, step-by-step output.   |

<details>
<summary>👉 Click to view sample verbose output</summary>

```text
[INFO] Starting pyNetAnalyzer Suite...
[INFO] Pinging default gateway 192.168.1.1...
[SUCCESS] Gateway is reachable. Latency: 1.5ms.
[INFO] Pinging primary DNS server 8.8.8.8...
[SUCCESS] DNS server is reachable. Latency: 9.2ms.
[INFO] Performing external IP lookup...
[SUCCESS] External IP: 123.45.67.89
[INFO] Test suite completed successfully.
```

</details>

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE.md` for more information.
```
