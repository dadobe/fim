# Import Necessary Libraries
import hashlib
import os
import time

# Define the Function to Calculate Hash
def calculate_hash(file_path):
    # Calculate the SHA-256 hash of a file
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read the file in chunks to support large files
        while chunk := file.read(4096):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

# Define the Function to Create Baseline
def create_baseline(file_path, baseline_file):
    # Calculate the baseline hash value and store it in a baseline file
    baseline_hash = calculate_hash(file_path)
    with open(baseline_file, "w") as f:
        f.write(baseline_hash)

# Define the Function to Check Integrity
def check_integrity(file_path, baseline_file):
    # Compare the current hash value with the baseline hash value
    current_hash = calculate_hash(file_path)
    with open(baseline_file, "r") as f:
        baseline_hash = f.read().strip()
    return current_hash == baseline_hash

# Main
if __name__ == "__main__":
    monitored_file = "/Users/dani/Documents/portfolio/FIM/tests/users.txt"
    baseline_file = "/Users/dani/Documents/portfolio/FIM/baseline.txt"

    # Create the baseline if it doesn't exist
    if not os.path.exists(baseline_file):
        print("Creating baseline...")
        create_baseline(monitored_file, baseline_file)
        print("Baseline created!")

    try:
        while True:
            # Check file integrity periodically
            if not check_integrity(monitored_file, baseline_file):
                print("File integrity violation detected!")
                # For simplicity, the alert will only print out a message
            else:
                print("File integrity check passed.")

            # Wait for 15 seconds before the next check (adjust as needed)
            time.sleep(15)

    except KeyboardInterrupt:
        print("Monitoring stopped.")