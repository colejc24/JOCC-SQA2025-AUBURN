import random
import string
import os
import yaml
from typing import List

from graphtaint import getYAMLFiles, readBashAsStr, mineSecretGraph
from parser import checkIfValidK8SYaml
from scanner import scanUserName

# Fuzzing helper functions
def random_string(length: int) -> str:
    """Generate a random string of the given length."""
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

def random_yaml() -> str:
    """Generate a random YAML string (simplified example)."""
    return f"key: {random_string(10)}\nvalue: {random_string(15)}"

def random_bash_script() -> str:
    """Generate a random bash script with some random content."""
    return f"#!/bin/bash\n{random_string(10)}\n{random_string(20)}"

def create_temp_yaml(content: str) -> str:
    """Create a temporary YAML file and return its path."""
    temp_file_path = "temp_file.yaml"
    with open(temp_file_path, "w") as f:
        f.write(content)
    return temp_file_path

def create_temp_bash_script(content: str) -> str:
    """Create a temporary bash script file and return its path."""
    temp_file_path = "temp_script.sh"
    with open(temp_file_path, "w") as f:
        f.write(content)
    return temp_file_path

# Fuzzing Functions

def fuzz_getYAMLFiles():
    """Fuzz testing for getYAMLFiles function."""
    print("Fuzzing getYAMLFiles")
    invalid_path = random_string(10)
    print(f"Testing with invalid directory path: {invalid_path}")
    # Expected to handle invalid path gracefully
    try:
        getYAMLFiles(invalid_path)
    except Exception as e:
        print(f"Error caught: {e}")

    # Fuzz with random YAML files
    for _ in range(5):
        random_yaml_content = random_yaml()
        temp_file = create_temp_yaml(random_yaml_content)
        print(f"Testing with random YAML file: {temp_file}")
        try:
            getYAMLFiles(temp_file)
        except Exception as e:
            print(f"Error caught: {e}")
        os.remove(temp_file)

def fuzz_readBashAsStr():
    """Fuzz testing for readBashAsStr function."""
    print("Fuzzing readBashAsStr")
    invalid_script = random_string(15)
    print(f"Testing with invalid bash script path: {invalid_script}")
    try:
        readBashAsStr(invalid_script)
    except Exception as e:
        print(f"Error caught: {e}")

    # Fuzz with random bash scripts
    for _ in range(5):
        random_script = random_bash_script()
        temp_script = create_temp_bash_script(random_script)
        print(f"Testing with random bash script: {temp_script}")
        try:
            readBashAsStr(temp_script)
        except Exception as e:
            print(f"Error caught: {e}")
        os.remove(temp_script)

def fuzz_checkIfValidK8SYaml():
    """Fuzz testing for checkIfValidK8SYaml function."""
    print("Fuzzing checkIfValidK8SYaml")
    invalid_yaml = random_yaml()  # Invalid YAML can be generated
    temp_file = create_temp_yaml(invalid_yaml)
    print(f"Testing with invalid Kubernetes YAML file: {temp_file}")
    try:
        checkIfValidK8SYaml(temp_file)
    except Exception as e:
        print(f"Error caught: {e}")
    os.remove(temp_file)

def fuzz_scanUserName():
    """Fuzz testing for scanUserName function."""
    print("Fuzzing scanUserName")
    invalid_usernames = [
        "",  # Empty string
        random_string(255),  # Too long username
        random_string(5),  # Short username
        random_string(20),  # Random alphanumeric
        random_string(10) + "!"  # Username with special char
    ]
    for username in invalid_usernames:
        print(f"Testing with invalid username: {username}")
        try:
            scanUserName(None, [username])  # Pass any value for k_ as we're testing the username
        except Exception as e:
            print(f"Error caught: {e}")

def fuzz_mineSecretGraph():
    """Fuzz testing for mineSecretGraph function."""
    print("Fuzzing mineSecretGraph")
    invalid_secret_dict = {"secret_key": random_string(10)}  # Example of a malformed secret dict
    random_yaml_content = random_yaml()
    temp_file = create_temp_yaml(random_yaml_content)
    print(f"Testing with invalid secret graph: {temp_file}")
    try:
        mineSecretGraph(temp_file, {}, invalid_secret_dict)
    except Exception as e:
        print(f"Error caught: {e}")
    os.remove(temp_file)

# Main fuzzing function to call all fuzz tests
def run_fuzz_tests():
    fuzz_getYAMLFiles()
    fuzz_readBashAsStr()
    fuzz_checkIfValidK8SYaml()
    fuzz_scanUserName()
    fuzz_mineSecretGraph()

if __name__ == "__main__":
    run_fuzz_tests()
