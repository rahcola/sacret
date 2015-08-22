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
import base64
from docopt import docopt
import hashlib
import os
import os.path
import subprocess
import sys
import tempfile


class Index(object):
    INDEX = "index.asc"

    def __init__(self, salt, names, directory):
        self.salt = salt
        self.names = names
        self.directory = directory
        self.modified = False

    def __len__(self):
        return len(self.names)

    def __getitem__(self, key):
        return self.names[key]

    def __iter__(self):
        return self.names.keys()

    def __contains__(self, item):
        return item in self.names

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None and self.modified:
            r = self.to_disk()
            if r != 0:
                path = os.path.join(self.directory, self.__class__.INDEX)
                cmd = ["gpg", "-q", "-e", "-a", "--output", path]
                raise subprocess.CalledProcessError(r, cmd)

    def keys(self):
        return self.names.keys()

    def add(self, name):
        self.names[name] = os.path.join(self.directory, hash_name(name, self.salt))
        self.modified = True

    def to_disk(self):
        path = os.path.join(self.directory, self.__class__.INDEX)
        with subprocess.Popen(["gpg", "-q", "-e", "-a", "--output", path],
                              universal_newlines=True,
                              stdin=subprocess.PIPE) as gpg:
            gpg.communicate("\n".join([self.salt] + list(self.keys())) + "\n")
            r = gpg.wait()
            self.modified = r != 0
            return r

    @classmethod
    def from_disk(cls, directory):
        path = os.path.join(directory, cls.INDEX)
        salt, *names = subprocess.check_output(["gpg", "-q", "-d", path],
                                               universal_newlines=True).splitlines()
        return cls(salt,
                   {name: os.path.join(directory, hash_name(name, salt))
                    for name in names},
                   directory)

    @classmethod
    def init(cls, directory):
        path = os.path.join(directory, cls.INDEX)
        if os.path.exists(path):
            print("index file {} exists".format(path), file=sys.stderr)
            return 1
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8")
        return cls(salt, {}, directory).to_disk()


def hash_name(name, salt):
    bytes = name.encode("utf-8") + base64.urlsafe_b64decode(salt)
    return base64.urlsafe_b64encode(hashlib.sha256(bytes).digest()).decode("utf-8")

def list_secrets(args):
    print("\n".join(Index.from_disk(args["--secrets"]).keys()))
    return 0

def show_secret(args):
    return subprocess.call(["gpg", "-q", "-d",
                            Index.from_disk(args["--secrets"])[args["<secret>"]]])

def copy_secret(args):
    with subprocess.Popen(["gpg", "-q", "-d",
                           Index.from_disk(args["--secrets"])[args["<secret>"]]],
                          stdout=subprocess.PIPE) as gpg:
        with subprocess.Popen(["head -q -n 1 | tr -d '\n' | xclip -selection clipboard"],
                              shell=True,
                              stdin=gpg.stdout) as head:
            gpg.stdout.close()
            return head.wait()

def edit_secret(args):
    if os.getenv("EDITOR") is None:
        print("please set EDITOR", file=sys.stderr)
        return 1
    with Index.from_disk(args["--secrets"]) as index:
        secret = args["<secret>"]
        if secret not in index:
            index.add(secret)
        secret_file = index[secret]
    dir = None
    shm = os.path.abspath(os.path.join(os.sep, "dev", "shm"))
    if os.path.isdir(shm):
        dir = shm
    with tempfile.NamedTemporaryFile(mode="w", dir=dir) as temp_file:
        if os.path.exists(secret_file):
            subprocess.check_call(["gpg", "-q", "-d", secret_file], stdout=temp_file)
        subprocess.check_call(["$EDITOR {}".format(temp_file.name)], shell=True)
        return subprocess.call(["gpg", "-q", "-e", "-a", "--output", secret_file,
                                temp_file.name])

def parse_command(arguments, actions):
    for command in actions:
        if arguments[command]:
            return actions[command]

if __name__ == "__main__":
    arguments = docopt(__doc__, version="sacret 0.0.1")
    actions = {
        "init": lambda args: Index.init(args["--secrets"]),
        "list": list_secrets,
        "show": show_secret,
        "copy": copy_secret,
        "edit": edit_secret
    }
    arguments["--secrets"] = os.path.expanduser(arguments["--secrets"])
    try:
        sys.exit(parse_command(arguments, actions)(arguments))
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
