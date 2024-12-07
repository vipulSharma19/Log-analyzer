import re
import csv
from collections import Counter, defaultdict

class LogAnalyzer:
    """A class to analyze server log files."""
    def __init__(self, log_file, csv_file, failed_login_threshold=10):
        self.log_file = log_file
        self.csv_file = csv_file
        self.failed_login_threshold = failed_login_threshold
        self.ip_regex = r'(\d+\.\d+\.\d+\.\d+)'  # Matching IPv4 addresses using REGEX
        self.endpoint_regex = r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (\S+)'  # Matching endpoints using REGEX
        self.status_regex = r'HTTP\/\d\.\d" (\d{3})'  # Matching HTTP status codes using REGEX
        self.log_lines = []

    def parse_log(self):
        """Reads the log file and loads its lines."""
        try:
            with open(self.log_file, 'r') as file:
                self.log_lines = file.readlines()
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found.")
            self.log_lines = []

    def count_requests_per_ip(self):
        """Counts the number of requests made by each IP address."""
        ip_counts = Counter(re.findall(self.ip_regex, " ".join(self.log_lines)))
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

    def find_most_accessed_endpoint(self):
        """Identifies the most accessed endpoint and its access count."""
        endpoints = re.findall(self.endpoint_regex, " ".join(self.log_lines))
        endpoint_counts = Counter(endpoints)
        return endpoint_counts.most_common(1)[0] if endpoint_counts else ("None", 0)

    def detect_suspicious_activity(self):
        """Detects IPs with failed login attempts exceeding the threshold."""
        suspicious_ips = defaultdict(int)
        for line in self.log_lines:
            ip_match = re.search(self.ip_regex, line)
            status_match = re.search(self.status_regex, line)
            if ip_match and status_match and status_match.group(1) == "401":
                suspicious_ips[ip_match.group(1)] += 1
        return {ip: count for ip, count in suspicious_ips.items() if count > self.failed_login_threshold}

    def save_to_csv(self, request_counts, most_accessed, suspicious_activities):
        """Saves analysis results to a CSV file."""
        try:
            with open(self.csv_file, mode="w", newline="") as file:
                writer = csv.writer(file)

                # Requests per IP
                writer.writerow(["Requests per IP"])
                writer.writerow(["IP Address", "Request Count"])
                writer.writerows(request_counts)

                # Most Accessed Endpoint
                writer.writerow([])
                writer.writerow(["Most Accessed Endpoint"])
                writer.writerow(["Endpoint", "Access Count"])
                writer.writerow(most_accessed)

                # Suspicious Activity
                writer.writerow([])
                writer.writerow(["Suspicious Activity"])
                writer.writerow(["IP Address", "Failed Login Count"])
                for ip, count in suspicious_activities.items():
                    writer.writerow([ip, count])
        except Exception as e:
            print(f"Error writing to CSV file: {e}")

    def display_results(self, request_counts, most_accessed, suspicious_activities):
        """Displays results in a formatted manner."""
        print("Requests per IP:")
        for ip, count in request_counts:
            print(f"{ip:<20} {count}")

        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

        print("\nSuspicious Activity Detected:")
        if suspicious_activities:
            for ip, count in suspicious_activities.items():
                print(f"{ip:<20} {count}")
        else:
            print("No suspicious activity detected.")

    def analyze(self):
        """Executes the full analysis workflow."""
        self.parse_log()
        if not self.log_lines:
            return

        # Performing analyses
        request_counts = self.count_requests_per_ip()
        most_accessed = self.find_most_accessed_endpoint()
        suspicious_activities = self.detect_suspicious_activity()

        # Display and save results
        self.display_results(request_counts, most_accessed, suspicious_activities)
        self.save_to_csv(request_counts, most_accessed, suspicious_activities)
        print(f"\nResults saved to '{self.csv_file}'.")


if __name__ == "__main__":
    analyzer = LogAnalyzer(
        log_file=r"data\sample.log", 
        csv_file=r"data\log_analysis_results.csv", 
        failed_login_threshold=10
    )
    analyzer.analyze()
