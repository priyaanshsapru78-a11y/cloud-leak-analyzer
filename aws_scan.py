import boto3
import re
import math
from datetime import datetime

# AWS connection
s3 = boto3.client("s3")

# Global variables
results = []
leak_count = 0
risk_score = 0

# Patterns
patterns = {
    "AWS Key": (r"AKIA[0-9A-Z]{16}", "HIGH"),
    "Password": (r"password\s*=\s*['\"]?[^'\"\n]+", "MEDIUM"),
    "Private Key": (r"-----BEGIN PRIVATE KEY-----", "CRITICAL"),
    "Email": (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "LOW"),
    "Phone Number": (r"\b\d{10}\b", "LOW"),
    "Credit Card": (r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", "CRITICAL")
}

# Context keywords
sensitive_keywords = ["password", "secret", "key", "token", "auth"]

# Entropy function
def calculate_entropy(text):
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log2(p) for p in prob])
    return entropy


# Bucket security
def check_bucket_security(bucket_name):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                msg = "WARNING: Bucket is PUBLIC!"
                results.append(msg)
                return

        results.append("Bucket is PRIVATE (Safe)")

    except Exception as e:
        results.append(f"Error checking bucket: {e}")


# Public objects
def check_public_objects(bucket_name):
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name)

        for obj in objects.get("Contents", []):
            key = obj["Key"]
            acl = s3.get_object_acl(Bucket=bucket_name, Key=key)

            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})

                if grantee.get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                    results.append(f"WARNING: Public file -> {key}")

    except Exception as e:
        results.append(f"Error checking public files: {e}")


# Scan bucket
def scan_bucket(bucket_name):
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)

        if "Contents" not in response:
            results.append("Bucket is empty")
            return

        for obj in response["Contents"]:
            key = obj["Key"]

            file_obj = s3.get_object(Bucket=bucket_name, Key=key)
            data = file_obj["Body"].read()

            # Skip binary files
            if b'\x00' in data:
                results.append(f"Skipping binary file: {key}")
                continue

            content = data.decode(errors="ignore")
            check_file(key, content)

    except Exception as e:
        results.append(f"Error scanning bucket: {e}")


# Intelligent detection
def check_file(filename, text):
    global leak_count, risk_score
    found = False

    # Rule-based
    for name, (pattern, severity) in patterns.items():
        if re.search(pattern, text):
            found = True
            leak_count += 1

            if severity == "CRITICAL":
                risk_score += 5
            elif severity == "HIGH":
                risk_score += 3
            elif severity == "MEDIUM":
                risk_score += 2
            else:
                risk_score += 1

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            result = f"[{timestamp}] | {severity} | {name} | File: {filename}"
            results.append(result)

    # Context detection
    for keyword in sensitive_keywords:
        if keyword in text.lower():
            results.append(f"Context Warning: '{keyword}' found in {filename}")

    # Entropy detection
    words = text.split()

    for word in words:
        if len(word) > 20:
            entropy = calculate_entropy(word)

            if entropy > 4.5:
                results.append(f"Possible Secret (High Entropy): {word[:10]}... in {filename}")
                leak_count += 1
                risk_score += 3

    # No leak case
    if not found:
        results.append(f"No leaks found in {filename}")


# MAIN function for Flask
def run_scan(bucket_name_input):
    global results, leak_count, risk_score

    # reset
    results = []
    leak_count = 0
    risk_score = 0

    results.append(f"Scanning bucket: {bucket_name_input}")

    check_bucket_security(bucket_name_input)
    check_public_objects(bucket_name_input)
    scan_bucket(bucket_name_input)

    results.append(f"Total leaks: {leak_count}")
    results.append(f"Risk Score: {risk_score}")

    return results