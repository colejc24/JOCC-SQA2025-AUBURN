import random
import string
import os
import yaml
import tempfile
import contextlib
import io
from typing import List

from graphtaint import getYAMLFiles, readBashAsStr, mineSecretGraph
from parser import checkIfValidK8SYaml
from scanner import scanUserName

def random_string(n): return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=n))
def random_yaml(): return f"key: {random_string(10)}\nvalue: {random_string(15)}"
def random_bash(): return f"#!/bin/bash\n{random_string(10)}\n{random_string(20)}"

def fuzz_getYAMLFiles():
    print("Fuzzing getYAMLFiles")
    bad = random_string(8)
    print(f" Testing with invalid directory path: {bad!r}")
    try:
        getYAMLFiles(bad)
    except Exception as e:
        print(f"  Error caught: {type(e).__name__}: {e}")

    for _ in range(3):
        # use NamedTemporaryFile so we get a unique .yaml
        tf = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        tf.write(random_yaml())
        tf.close()
        print(f" Testing with random YAML file: {tf.name!r}")
        try:
            getYAMLFiles(tf.name)
        except Exception as e:
            print(f"  Error caught: {type(e).__name__}: {e}")
        finally:
            os.unlink(tf.name)

def fuzz_readBashAsStr():
    print("Fuzzing readBashAsStr")
    bad = random_string(12)
    print(f" Testing with invalid bash script path: {bad!r}")
    try:
        readBashAsStr(bad)
    except Exception as e:
        print(f"  Error caught: {type(e).__name__}: {e}")

    for _ in range(3):
        tf = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
        tf.write(random_bash())
        tf.close()
        print(f" Testing with random bash script: {tf.name!r}")
        try:
            readBashAsStr(tf.name)
        except Exception as e:
            print(f"  Error caught: {type(e).__name__}: {e}")
        finally:
            os.unlink(tf.name)

def fuzz_checkIfValidK8SYaml():
    print("Fuzzing checkIfValidK8SYaml")
    tf = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    tf.write(random_yaml())
    tf.close()
    print(f" Testing with invalid Kubernetes YAML file: {tf.name!r}")
    buf = io.StringIO()
    # suppress any prints inside checkIfValidK8SYaml
    with contextlib.redirect_stdout(buf):
        try:
            checkIfValidK8SYaml(tf.name)
        except Exception as e:
            print(f"  Error caught: {type(e).__name__}: {e}")
    os.unlink(tf.name)

def fuzz_scanUserName():
    print("Fuzzing scanUserName")
    cases = ["", random_string(255), random_string(5), random_string(20), random_string(10)+"!"]
    for u in cases:
        print(f" Testing with invalid username: {u!r}")
        try:
            scanUserName(None, [u])
        except Exception as e:
            print(f"  Error caught: {type(e).__name__}: {e}")

def fuzz_mineSecretGraph():
    print("Fuzzing mineSecretGraph")
    tf = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    tf.write(random_yaml())
    tf.close()
    print(f" Testing with invalid secret graph: {tf.name!r}")
    try:
        mineSecretGraph(tf.name, {}, {"secret_key": random_string(8)})
    except Exception as e:
        print(f"  Error caught: {type(e).__name__}: {e}")
    finally:
        os.unlink(tf.name)

if __name__ == "__main__":
    fuzz_getYAMLFiles()
    fuzz_readBashAsStr()
    fuzz_checkIfValidK8SYaml()
    fuzz_scanUserName()
    fuzz_mineSecretGraph()