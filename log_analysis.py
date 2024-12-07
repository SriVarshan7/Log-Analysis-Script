import csv
from collections import defaultdict, Counter
import re

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = r'C:\Users\gowtham\Desktop\Py intern\sample.log'
OUTPUT_FILE = 'log_analysis_results.csv'

def parse_log(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    return lines

# IP address
def count_requests_per_ip(log_lines):
    ip_counts = Counter()
    for line in log_lines:
        match = re.match(r'^(\S+)', line)  
        # Matches the first word IP
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

# frequently accessed 
def most_accessed_endpoint(log_lines):
    endpoint_counts = Counter()
    for line in log_lines:
        match = re.search(r'"[A-Z]+\s(/[^ ]*)', line)  
        # Matches the URL
        if match:
            endpoint_counts[match.group(1)] += 1
    most_common = endpoint_counts.most_common(1)
    return most_common[0] if most_common else (None, 0)

# detect suspicious activity
def detect_suspicious_activity(log_lines):
    failed_logins = defaultdict(int)
    for line in log_lines:
        if ' 401 ' in line or 'Invalid credentials' in line:
            match = re.match(r'^(\S+)', line)  
            # Matches the IP at the start
            if match:
                failed_logins[match.group(1)] += 1
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return flagged_ips

# save results
def save_results_to_csv(ip_counts, most_accessed, suspicious_activity):
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([]) 
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    log_lines = parse_log(LOG_FILE)

    #log file
    ip_counts = count_requests_per_ip(log_lines)
    most_accessed = most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)

    print("IP Address           Request Count")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed[0]:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No endpoint found.")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # results to CSV
    save_results_to_csv(ip_counts, most_accessed, suspicious_activity)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
