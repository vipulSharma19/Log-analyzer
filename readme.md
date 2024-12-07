Here's a detailed and professional `README.md` for your log analysis project:

---

# **Log Analyzer**

## **Overview**

Log Analyzer is a Python tool designed to process server log files for extracting and analyzing key information. The script helps identify trends, detect suspicious activities, and generate meaningful insights such as:
- Requests per IP address
- The most frequently accessed endpoints
- Suspicious activities (e.g., potential brute force attempts)

The tool outputs results in a structured format on the terminal and saves them to a CSV file for further analysis.

---

## **Features**

1. **Requests per IP Address**:  
   Counts the number of requests made by each IP address and displays them in descending order of request counts.

2. **Most Frequently Accessed Endpoint**:  
   Identifies the endpoint (e.g., `/home`, `/login`) that was accessed the highest number of times.

3. **Suspicious Activity Detection**:  
   Flags IP addresses with failed login attempts exceeding a configurable threshold.

4. **Export Results to CSV**:  
   Saves results to a CSV file with separate sections for requests per IP, the most accessed endpoint, and flagged suspicious activities.

---

## **Installation**

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/log-analyzer.git
   ```
2. Navigate to the project directory:
   ```bash
   cd log-analyzer
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## **Usage**

### **Command to Run**:
Run the script with the log file path specified in the configuration:
```bash
python src/log_analyzer.py
```

### **Input File**:
The log file should be placed in the `data/` directory. The default input file is `data/sample.log`.  

### **Output File**:
Results will be saved to `data/log_analysis_results.csv` with the following sections:
- **Requests per IP**
- **Most Accessed Endpoint**
- **Suspicious Activities**

---

## **Configuration**

The following parameters are configurable in the script (`log_analyzer.py`):
- **Log File Path**: Set the log file name/path in the `LOG_FILE` variable.
- **Output CSV File Path**: Change the output file path in the `CSV_FILE` variable.
- **Failed Login Threshold**: Modify the value of `FAILED_LOGIN_THRESHOLD` to set the maximum allowed failed login attempts before flagging.

---

## **Output Example**

### **Terminal Output**:
```plaintext
Requests per IP:
192.168.1.1          234
203.0.113.5          187
10.0.0.2             92

Most Frequently Accessed Endpoint:
/home (Accessed 403 times)

Suspicious Activity Detected:
192.168.1.100        56
203.0.113.34         12
```

### **CSV Output**:
The CSV file will be structured as follows:
```csv
Requests per IP
IP Address,Request Count
192.168.1.1,234
203.0.113.5,187
...

Most Accessed Endpoint
Endpoint,Access Count
/home,403

Suspicious Activity
IP Address,Failed Login Count
192.168.1.100,56
203.0.113.34,12
...
```

---


---

## **Project Structure**

```plaintext
log-analyzer/
│
├── src/                 # Source code
│   ├── log_analyzer.py  # Main script with the LogAnalyzer class
│
├── data/                # Folder for input and output data
│   ├── sample.log       # Sample log file (example input)
│   ├── log_analysis_results.csv  # Output CSV file (generated)
│
├── README.md            # Project documentation
├── requirements.txt     # Python dependencies
```

---

## **Dependencies**

All dependencies are listed in `requirements.txt`. Install them using:
```bash
pip install -r requirements.txt
```

---


## **Author**

Developed by [Vipul Sharma].  
For inquiries, please reach out at [sharmavipul694@gmail.com].

--- 

---

This `README.md` is comprehensive, making your project accessible and professional on GitHub. Let me know if you need further customizations!