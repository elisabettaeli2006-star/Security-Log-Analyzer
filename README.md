# Security-Log-Analyzer
# Security Log Analyzer: Python Automation

## Overview
This project involves the development of a custom Python script to automate the analysis of server authentication logs. The objective is to programmatically parse log files, identify failed login attempts, and detect potential Brute-Force attacks by tracking the frequency of failures per IP address.

## Environment & Tools
* **Environment:** Kali Linux.
* **Core Language:** Python 3.
* **Concepts Utilized:** File I/O operations, String manipulation (parsing), Dictionary data structures for frequency counting, Conditional logic.

## Execution Steps

### 1. Log Generation Simulation
A simulated SSH authentication log file (`auth.log`) was generated to represent a realistic server environment. This file included a mix of successful logins, isolated failed attempts, and a sequence of rapid failures indicative of a brute-force attack.

### 2. Python Script Development
A Python script (`analyzer.py`) was written to process the log file.
* The script opens the file and reads it line by line to minimize memory consumption.
* It filters lines containing the specific "Failed password" string.
* It tokenizes the string to extract the source IP address (the last element).
* It utilizes a Dictionary to maintain a persistent count of failures per IP.
* Finally, it iterates through the results, triggering a "CRITICAL ALERT" if an IP exceeds a threshold of 5 failed attempts.

**The Script:**
```python
# In Python, we don't need to include libraries like <stdio.h> or <string.h> for basic tasks.

# We create a Dictionary (in C this would be an Array / Hash Map).
# It will store the IP and how many times it failed the password. ex: {"10.0.0.5": 6}
ip_count = {}

print("Starting log file analysis...\n")

# We open the file (in C you would use fopen).
# "with open" automatically closes it at the end, so we no longer need fclose()!
with open("auth.log", "r") as log_file:
    
    # We read the file line by line (in C you would use fgets in a while loop)
    for line in log_file:
        
        # We look for the keywords (in C you would use strstr to find a substring)
        if "Failed password" in line:
            
            # We split the sentence into words separated by space (in C you would use strtok)
            words = line.split()
            
            # We extract the IP. In our log structure, the IP is the last word.
            # Python is brilliant: the [-1] index automatically takes the last element!
            ip = words[-1]
            
            # We check if we have seen this IP before
            if ip in ip_count:
                ip_count[ip] += 1 # Increment (like in C: ip_count++)
            else:
                ip_count[ip] = 1  # Add it with the value 1

# The analysis is done. Now we iterate through the results and display alerts.
print("=== SCAN RESULTS ===")
for ip, failure_count in ip_count.items():
    
    # Grammar fix: use "attempt" for 1, and "attempts" for more
    word = "attempt" if failure_count == 1 else "attempts"
    
    if failure_count > 5:
        print(f"[CRITICAL ALERT] Brute-Force attack detected from IP: {ip} ({failure_count} {word})")
    else:
        print(f"[INFO] Isolated failed authentication from IP: {ip} ({failure_count} {word})")
