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
    def __init__(self, salt, names):
        self.salt = salt
        self.names = names

    def __len__(self):
        return len(self.names)

    def __getitem__(self, key):
        return self.names[key]

    def __iter__(self):
        return self.names.keys()

    def keys(self):
        return self.names.keys()

    @classmethod
    def from_file(cls, path):
        salt, *names = read_encrypted(path).splitlines()
        return cls(salt, {name: name_to_file(name, salt) for name in names})


def read_encrypted(path):
    p = subprocess.Popen(["gpg", "-d", path],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    text, err = p.communicate()
    if p.returncode > 0:
        print(err.decode("utf-8"), end="", file=sys.stderr)
        sys.exit(1)
    return text.decode("utf-8")

def name_to_file(name, salt):
    bytes = name.encode("utf-8") + base64.urlsafe_b64decode(salt)
    return base64.urlsafe_b64encode(hashlib.sha256(bytes).digest()).decode("utf-8")

def read_index(secrets):
    return Index.from_file(os.path.join(secrets, "index.asc"))

def read_secret(secrets, name):
    f = os.path.join(secrets, read_index(secrets)[name])
    return read_encrypted(f)

def init_secrets(args):
    index = os.path.join(args.secrets, "index.asc")
    if os.path.exists(args.secrets):
        print("index file {} exists".format(index), file=sys.stderr)
        sys.exit(1)
    p = subprocess.Popen(["gpg", "-e", "-a",
                          "--output", index],
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    salt = base64.urlsafe_b64encode(os.urandom(16))
    err = p.communicate(salt + b"\n")[1]
    if p.returncode > 0:
        print(err, end="", file=sys.stderr)
        sys.exit(1)

def list_secrets(args):
    print("\n".join(read_index(args.secrets).keys()))

def show_secret(args):
    print(read_secret(args.secrets, args.name), end="")

def copy_secret(args):
    secret = read_secret(args.secrets, args.name).splitlines()[0]
    p = subprocess.Popen(["xclip", "-selection", "clipboard"],
                         stdin=subprocess.PIPE)
    p.communicate(secret.encode("utf-8"))

def edit_secret(args):
    secret_file = os.path.join(args.secrets, read_index(args.secrets)[args.name])
    try:
        f, temp_file = tempfile.mkstemp(text=True)
        subprocess.check_call(["gpg", "-d", secret_file], stdout=f)
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
    p.set_defaults(command=init_secrets)

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
