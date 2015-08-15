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
    def __init__(self, salt, names, sacret_dir):
        self.salt = salt
        self.names = names
        self.sacret_dir = sacret_dir

    def __len__(self):
        return len(self.names)

    def __getitem__(self, key):
        return self.names[key]

    def __iter__(self):
        return self.names.keys()

    def keys(self):
        return self.names.keys()

    @classmethod
    def from_disk(cls, sacret_dir):
        salt, *names = read_encrypted(os.path.join(sacret_dir, "index.asc")).splitlines()
        return cls(salt,
                   {name: os.path.join(sacret_dir, hash_name(name, salt))
                    for name in names},
                   sacret_dir)

    @classmethod
    def create(cls, sacret_dir):
        path = os.path.join(sacret_dir, "index.asc")
        if os.path.exists(path):
            print("index file {} exists".format(path), file=sys.stderr)
            sys.exit(1)
        p = subprocess.Popen(["gpg", "-e", "-a", "--output", path],
                             stdin=subprocess.PIPE)
        salt = base64.urlsafe_b64encode(os.urandom(16))
        p.communicate(salt + b"\n")
        if p.returncode != 0:
            sys.exit(p.returncode)
        return cls(salt, {}, sacret_dir)

def read_encrypted(path):
    p = subprocess.Popen(["gpg", "-q", "-d", path], stdout=subprocess.PIPE)
    text = p.communicate()[0]
    if p.returncode != 0:
        sys.exit(1)
    return text.decode("utf-8")

def hash_name(name, salt):
    bytes = name.encode("utf-8") + base64.urlsafe_b64decode(salt)
    return base64.urlsafe_b64encode(hashlib.sha256(bytes).digest()).decode("utf-8")

def list_secrets(args):
    print("\n".join(Index.from_disk(args.secrets).keys()))

def show_secret(args):
    print(read_encrypted(Index.from_disk(args.secrets)[args.name]), end="")

def copy_secret(args):
    gpg = subprocess.Popen(["gpg", "-d", Index.from_disk(args.secrets)[args.name]],
                           stdout=subprocess.PIPE)
    head = subprocess.Popen(["head -q -n 1 | tr -d '\n' | xclip -selection clipboard"],
                            shell=True,
                            stdin=gpg.stdout)
    gpg.stdout.close()
    if head.wait() != 0:
        sys.exit(head.returncode)

def edit_secret(args):
    secret_file = Index.from_disk(args.secrets)[args.name]
    try:
        f, temp_file = tempfile.mkstemp(text=True)
        subprocess.check_call(["gpg", "-q", "-d", secret_file], stdout=f)
        subprocess.check_call(["$EDITOR {}".format(temp_file)], shell=True)
        subprocess.check_call(["gpg", "-e", "-a", "--output", secret_file, temp_file])
    finally:
        os.close(f)
        os.remove(temp_file)

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
    p.set_defaults(command=lambda args: Index.create(args.sercrets))

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
    args.command(args)
