#!/usr/bin/env python
"""Usage:
  sacret.py init [--secrets <dir>] <gpg_name>
  sacret.py list [--secrets <dir>]
  sacret.py (show | copy) [--secrets <dir>] <secret>
  sacret.py edit [--secrets <dir>] <gpg_name> <secret>
  sacret.py (-h | --help | -v | --version)

Options:
  -s <dir> --secrets <dir>  Directory of secrets. [default: ~/.sacret]
  -h --help                 Show this help.
  -v --version              Show version.

"""
import binascii
from docopt import docopt
import hashlib
import os
import os.path
import subprocess
import sys
import tempfile


decrypt = ["gpg", "-q", "--batch", "-d"]
encrypt = ["gpg", "-q", "--batch", "-a", "-e"]

def read_salt(index):
    with subprocess.Popen(decrypt + [index], stdout=subprocess.PIPE) as gpg:
        with subprocess.Popen(["head -n 1 | tr -d '\n'"],
                              shell=True,
                              universal_newlines=True,
                              stdin=gpg.stdout,
                              stdout=subprocess.PIPE) as p:
            gpg.stdout.close()
            salt = p.communicate()[0]
            if p.poll() != 0:
                sys.exit(p.poll())
            return bytearray.fromhex(salt)

def name_hash(name, salt):
    return hashlib.sha256(name.encode() + salt).hexdigest()

def init_secrets(args):
    path = os.path.join(args["--secrets"], "index.asc")
    salt = binascii.hexlify(os.urandom(16))
    with subprocess.Popen(encrypt + ["-r", args["<gpg_name>"], "--output", path],
                          stdin=subprocess.PIPE) as gpg:
        gpg.communicate(salt + b"\n")
        if gpg.poll() != 0:
            sys.exit(gpg.poll())

def list_secrets(args):
    index = os.path.join(args["--secrets"], "index.asc")
    with subprocess.Popen(decrypt + [index], stdout=subprocess.PIPE) as gpg:
        with subprocess.Popen(["tail", "-n", "+2"], stdin=gpg.stdout) as tail:
            gpg.stdout.close()
            if tail.wait() != 0:
                sys.exit(tail.returncode)

def show_secret(args):
    index = os.path.join(args["--secrets"], "index.asc")
    salt = read_salt(index)
    secret = os.path.join(args["--secrets"], name_hash(args["<secret>"], salt))
    subprocess.check_call(decrypt + [secret])

def copy_secret(args):
    index = os.path.join(args["--secrets"], "index.asc")
    salt = read_salt(index)
    secret = os.path.join(args["--secrets"], name_hash(args["<secret>"], salt))
    with subprocess.Popen(decrypt + [secret], stdout=subprocess.PIPE) as gpg:
        with subprocess.Popen(["head -n 1 | tr -d '\n' | xclip -selection clipboard"],
                              shell=True,
                              stdin=gpg.stdout) as xclip:
            gpg.stdout.close()
            if xclip.wait() != 0:
                sys.exit(xclip.returncode)

def add_secret(index, gpg_name, secret):
    content = subprocess.check_output(decrypt + [index], universal_newlines=True)
    if secret not in content.splitlines():
        with subprocess.Popen(encrypt + ["-r", gpg_name, "--yes", "--output", index],
                              universal_newlines=True,
                              stdin=subprocess.PIPE) as gpg:
            gpg.communicate(content + secret + "\n")
            if gpg.poll() != 0:
                sys.exit(gpg.poll())

def tmp_dir():
    shm = os.path.abspath(os.path.join(os.sep, "dev", "shm"))
    if os.path.isdir(shm):
        return shm

def edit_secret(args):
    if os.getenv("EDITOR") is None:
        print("please set EDITOR", file=sys.stderr)
        sys.exit(1)
    index = os.path.join(args["--secrets"], "index.asc")
    add_secret(index, args["<gpg_name>"], args["<secret>"])
    salt = read_salt(index)
    secret = os.path.join(args["--secrets"], name_hash(args["<secret>"], salt))
    with tempfile.NamedTemporaryFile(mode="w", dir=tmp_dir()) as temp_file:
        if os.path.exists(secret):
            subprocess.check_call(decrypt + [secret], stdout=temp_file)
        subprocess.check_call(["$EDITOR {}".format(temp_file.name)], shell=True)
        subprocess.check_call(encrypt + ["-r", args["<gpg_name>"], "--yes",
                                         "--output", secret, temp_file.name])

def parse_command(arguments, actions):
    for command in actions:
        if arguments[command]:
            return actions[command]

if __name__ == "__main__":
    arguments = docopt(__doc__, version="sacret 0.0.1")
    actions = {
        "init": init_secrets,
        "list": list_secrets,
        "show": show_secret,
        "copy": copy_secret,
        "edit": edit_secret
    }
    arguments["--secrets"] = os.path.expanduser(arguments["--secrets"])
    try:
        parse_command(arguments, actions)(arguments)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
