# pyNetAnalyzer

> An advanced, command-line network diagnostic tool for Python. `pyNetAnalyzer` runs a variety of tests, logs results to a local database, and allows for querying past performance data.

## Features

* **Multi-Faceted Testing:** Run tests for ping, latency, jitter, packet loss, and traceroute.
* **Persistent Storage:** Automatically saves all test results to a local SQLite database for historical analysis.
* **Flexible Output:** View results in a human-readable format or export as JSON for use in other applications.
* **Query Past Results:** Easily retrieve and display the results of any previous test run using its unique ID.
* **Customizable Test Suites:** Run all tests at once or specify individual tests to perform.

## Getting Started

Follow these instructions to get the project up and running.

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
    ```bash
    pip install -r requirements.txt
    ```
4.  **Initialize the Database:**
    The first time you run the script, it will automatically create a `network_tests.db` file to store results.

## Usage

`pyNetAnalyzer` now has a more powerful set of commands to run tests and manage results.

**Basic Example (Run all tests):**
Execute the main script with `sudo` permissions to run the full diagnostic suite.

```bash
sudo python3 pyNetAnalyzer.py
```

**Running Specific Tests:**
You can specify one or more tests to run.

```bash
# Run only the ping and traceroute tests
sudo python3 pyNetAnalyzer.py --test ping traceroute
```

**Querying Past Results:**
Retrieve a previous test run from the database by its ID.

```bash
# Get the results from the test run with ID 11
python3 pyNetAnalyzer.py --query 11
```

**JSON Output:**
Export results in JSON format. This is useful for parsing with other scripts.

```bash
# Run all tests and output the results as JSON
sudo python3 pyNetAnalyzer.py --format json
```

### Command-Line Arguments

| Argument | Type | Description |
| :--- | :--- | :--- |
| `--test` | list | Specify one or more tests to run (e.g., `ping`, `jitter`, `traceroute`). Defaults to all tests. |
| `--name` | string | Attach a customer name or identifier to the test run for easier tracking. |
| `--export` | flag | **(Deprecated)** Use `--format json` and redirect output instead (e.g., `... > results.json`). |
| `--verbose` | flag | Enable detailed, step-by-step output during the test execution. |
| `--query` | integer | Retrieve and display a specific test result from the database by its ID. |
| `--format` | string | Set the output format. Options are `text` (default) or `json`. |
| `--list-tests`| flag | Display a list of all available tests you can run. |

## Contributing

Contributions are welcome! Please follow the standard fork and pull request workflow.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/NewTest`)
3.  Commit your Changes (`git commit -m 'Add NewTest'`)
4.  Push to the Branch (`git push origin feature/NewTest`)
5.  Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE.md` for more information.

