#!/usr/bin/env python

import argparse
import base64
import hashlib
import os
import os.path
import subprocess
import sys
import tempfile


class Index(object):
    INDEX = "index.asc"

    def __init__(self, salt, names, sacret_dir):
        self.salt = salt
        self.names = names
        self.sacret_dir = sacret_dir
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
                path = os.path.join(self.sacret_dir, self.__class__.INDEX)
                cmd = ["gpg", "-q", "-e", "-a", "--output", path]
                raise subprocess.CalledProcessError(r, cmd)

    def keys(self):
        return self.names.keys()

    def add(self, name):
        self.names[name] = os.path.join(self.sacret_dir,
                                        hash_name(name, self.salt))
        self.modified = True

    def to_disk(self):
        path = os.path.join(self.sacret_dir, self.__class__.INDEX)
        with subprocess.Popen(["gpg", "-q", "-e", "-a", "--output", path],
                              universal_newlines=True,
                              stdin=subprocess.PIPE) as gpg:
            gpg.communicate("\n".join([self.salt] + list(self.keys())) + "\n")
            r = gpg.wait()
            self.modified = r != 0
            return r

    @classmethod
    def from_disk(cls, sacret_dir):
        path = os.path.join(sacret_dir, cls.INDEX)
        salt, *names = subprocess.check_output(["gpg", "-q", "-d", path],
                                               universal_newlines=True).splitlines()
        return cls(salt,
                   {name: os.path.join(sacret_dir, hash_name(name, salt))
                    for name in names},
                   sacret_dir)

    @classmethod
    def init(cls, sacret_dir):
        path = os.path.join(sacret_dir, cls.INDEX)
        if os.path.exists(path):
            print("index file {} exists".format(path), file=sys.stderr)
            return 1
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8")
        return cls(salt, {}, sacret_dir).to_disk()


def hash_name(name, salt):
    bytes = name.encode("utf-8") + base64.urlsafe_b64decode(salt)
    return base64.urlsafe_b64encode(hashlib.sha256(bytes).digest()).decode("utf-8")

def list_secrets(args):
    print("\n".join(Index.from_disk(args.secrets).keys()))
    return 0

def show_secret(args):
    return subprocess.call(["gpg", "-q", "-d",
                            Index.from_disk(args.secrets)[args.name]])

def copy_secret(args):
    with subprocess.Popen(["gpg", "-q", "-d", Index.from_disk(args.secrets)[args.name]],
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
    with Index.from_disk(args.secrets) as index:
        if args.name not in index:
            index.add(args.name)
        secret_file = index[args.name]
    with tempfile.NamedTemporaryFile(mode="w") as temp_file:
        if os.path.exists(secret_file):
            subprocess.check_call(["gpg", "-q", "-d", secret_file], stdout=temp_file)
        subprocess.check_call(["$EDITOR {}".format(temp_file.name)], shell=True)
        return subprocess.call(["gpg", "-q", "-e", "-a", "--output", secret_file,
                                temp_file.name])

def argument_secrets(parser):
    default = os.getenv("SACRET_DIR", default=os.path.expanduser("~/.sacret"))
    parser.add_argument("-s", "--secrets",
                        help="directory of secrets",
                        default=default,
                        metavar="<directory>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plain file secret manager.")
    parser.set_defaults(command=lambda a: parser.print_help())
    subparsers = parser.add_subparsers(title="commands",
                                       description=None,
                                       metavar="<command>")
    p = subparsers.add_parser("init",
                              description="Create an empty index",
                              help="create an empty index")
    argument_secrets(p)
    p.set_defaults(command=lambda args: Index.init(args.sercrets))

    p = subparsers.add_parser("list",
                              description="List all secrets",
                              help="list all secrets")
    argument_secrets(p)
    p.set_defaults(command=list_secrets)

    p = subparsers.add_parser("show",
                              description="Show a secret",
                              help="show a secret")
    argument_secrets(p)
    p.add_argument("name", help="name of a secret")
    p.set_defaults(command=show_secret)

    p = subparsers.add_parser("copy",
                              description="Copy first line of a secret to clipboard",
                              help="copy first line of a secret to clipboard")
    argument_secrets(p)
    p.add_argument("name", help="name of a secret")
    p.set_defaults(command=copy_secret)

    p = subparsers.add_parser("edit",
                              description="Edit a secret",
                              help="edit a secret")
    argument_secrets(p)
    p.add_argument("name", help="name of a secret")
    p.set_defaults(command=edit_secret)

    args = parser.parse_args()
    try:
        sys.exit(args.command(args))
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
