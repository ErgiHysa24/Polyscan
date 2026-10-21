import hashlib
import os
import pickle
import subprocess


def ping(host):
    return os.system("ping -c 1 " + host)  # command injection


def run(cmd):
    return subprocess.run(cmd, shell=True)  # shell=True


def fingerprint(data):
    return hashlib.md5(data).hexdigest()  # weak hash


def load(blob):
    return pickle.loads(blob)  # unsafe deserialization
