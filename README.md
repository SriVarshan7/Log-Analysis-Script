# Log Analysis Script

This Python script analyzes web server log files to extract and summarize key information, including:
- The number of requests made by each IP address.
- The most frequently accessed endpoint.
- Suspicious activities such as potential brute force login attempts.

## Features

1. **Requests per IP Address**:
   - Extracts all IP addresses from the log file.
   - Counts the number of requests made by each IP.
   - Displays the results in descending order.

2. **Most Frequently Accessed Endpoint**:
   - Identifies the endpoint (URL or resource path) accessed the most times.
   - Outputs the endpoint and the number of accesses.

3. **Suspicious Activity Detection**:
   - Detects IPs with failed login attempts exceeding a configurable threshold (default: 10 attempts).
   - Supports detection based on HTTP `401` status codes or the phrase `Invalid credentials`.

4. **CSV Output**:
   - Saves the analysis results into a CSV file (`log_analysis_results.csv`), including:
     - Requests per IP.
     - Most accessed endpoint.
     - Suspicious activity.

## Requirements

- Python 3.6 or higher.

## Setup

1. Clone the repository or download the script.
2. Ensure that you have the required Python version installed.
3. Save your log file in the project directory (default name: `sample.log`).

## Usage

1. Open the script (`log_analysis.py`) and update the `LOG_FILE` path if needed:
    ```python
    LOG_FILE = r'C:\path\to\your\logfile.log'
    ```

2. Run the script:
    ```bash
    python log_analysis.py
    ```

3. View the results:
    - On the terminal:
        - IP request counts.
        - Most accessed endpoint.
        - Suspicious activities.
    - In the CSV file: `log_analysis_results.csv`.

## Example Output

### Terminal
