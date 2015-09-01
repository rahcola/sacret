#!/usr/bin/env python
"""Usage:
  sacret.py (init | list) [--secrets <dir>]
  sacret.py (show | copy | edit) [--secrets <dir>] <secret>
  sacret.py (-h | --help | -v | --version)

Options:
  -s <dir> --secrets <dir>  Directory of secrets. [default: ~/.sacret]
  -h --help                 Show this help.
  -v --version              Show version.

"""
from docopt import docopt
import os
import os.path
import sacretindex
import subprocess
import sys
import tempfile
import uuid


decrypt = ["gpg", "-q", "--batch", "-d"]
encrypt = ["gpg", "-q", "--batch", "-a", "--symmetric"]

def init_secrets(args):
    sacretindex.init(args["index"])

def list_secrets(args):
    print('\n'.join(sacretindex.list_keys(args["index"])))

def show_secret(args):
    try:
        path = os.path.join(args["--secrets"],
                            sacretindex.get(args["index"], args["<secret>"]))
        subprocess.check_call(decrypt + [path])
    except KeyError:
        sys.stderr.write("no secret {} found\n".format(args["<secret>"]))
        sys.exit(1)

def copy_secret(args):
    try:
        path = os.path.join(args["--secrets"],
                            sacretindex.get(args["index"], args["<secret>"]))
    except KeyError:
        sys.stderr.write("no secret {} found\n".format(args["<secret>"]))
        sys.exit(1)
    with subprocess.Popen(decrypt + [path], stdout=subprocess.PIPE) as gpg:
        with subprocess.Popen(["head -n 1 | tr -d '\n' | xclip -selection clipboard"],
                              shell=True,
                              stdin=gpg.stdout) as xclip:
            gpg.stdout.close()
            if xclip.wait() != 0:
                sys.exit(xclip.returncode)

def tmp_dir():
    shm = os.path.abspath(os.path.join(os.sep, "dev", "shm"))
    if os.path.isdir(shm):
        return shm

def edit_secret(args):
    if os.getenv("EDITOR") is None:
        sys.stderr.write("please set EDITOR\n")
        sys.exit(1)
    sacretindex.add(args["index"], args["<secret>"], str(uuid.uuid4()))
    secret_path = os.path.join(args["--secrets"],
                               sacretindex.get(args["index"], args["<secret>"]))
    with tempfile.NamedTemporaryFile(mode="w", dir=tmp_dir()) as temp_file:
        if os.path.exists(secret_path):
            subprocess.check_call(decrypt + [secret_path], stdout=temp_file)
        subprocess.check_call(["$EDITOR {}".format(temp_file.name)], shell=True)
        subprocess.check_call(encrypt + ["--yes", "--output", secret_path,
                                         temp_file.name])

def parse_command(arguments, actions):
    for command in actions:
        if arguments[command]:
            return actions[command]

if __name__ == "__main__":
    arguments = docopt(__doc__, version="sacret.py 0.0.2")
    actions = {
        "init": init_secrets,
        "list": list_secrets,
        "show": show_secret,
        "copy": copy_secret,
        "edit": edit_secret
    }
    arguments["--secrets"] = os.path.expanduser(arguments["--secrets"])
    arguments["index"] = os.path.join(arguments["--secrets"], "index.asc")
    try:
        parse_command(arguments, actions)(arguments)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output.decode())
        sys.exit(e.returncode)
