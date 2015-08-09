#!/usr/bin/env python

import argparse
import base64
import hashlib
import os.path
import subprocess
import sys


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

def read_index(index):
    salt, *names = read_encrypted(index).splitlines()
    return {name: name_to_file(name, salt) for name in names}

def read_secret(index, name):
    f = os.path.join(os.path.dirname(index), read_index(index)[name])
    return read_encrypted(f)

def init_secrets(args):
    if os.path.exists(args.index):
        print("index file {} exists".format(args.index), file=sys.stderr)
        sys.exit(1)
    p = subprocess.Popen(["gpg", "-e", "-a",
                          "--output", args.index],
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    salt = base64.urlsafe_b64encode(os.urandom(16))
    err = p.communicate(salt + b"\n")[1]
    if p.returncode > 0:
        print(err, end="", file=sys.stderr)
        sys.exit(1)

def list_secrets(args):
    print("\n".join(read_index(args.index).keys()))

def show_secret(args):
    print(read_secret(args.index, args.name), end="")

def copy_secret(args):
    secret = read_secret(args.index, args.name).splitlines()[0]
    p = subprocess.Popen(["xclip", "-selection", "clipboard"],
                         stdin=subprocess.PIPE)
    p.communicate(secret.encode("utf-8"))

def add_index_argument(parser):
    parser.add_argument("-i", "--index",
                        help="encrypted index of secrets",
                        default=os.path.expanduser("~/.sacret/index.asc"),
                        metavar="<path>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plain file secret manager.")
    parser.set_defaults(command=lambda args: parser.print_help())
    subparsers = parser.add_subparsers(description=None, metavar="<command>")

    init_parser = subparsers.add_parser("init",
                                        description="Create an index of secrets.",
                                        help="create an index of secrets")
    add_index_argument(init_parser)
    init_parser.set_defaults(command=init_secrets)

    list_parser = subparsers.add_parser("list",
                                        description="List the names of the secrets.",
                                        help="list the names of the secrets")
    add_index_argument(list_parser)
    list_parser.set_defaults(command=list_secrets)

    show_parser = subparsers.add_parser("show",
                                        description="Show the secret.",
                                        help="show the secret")
    show_parser.add_argument("name", help="name of the secret")
    add_index_argument(show_parser)
    show_parser.set_defaults(command=show_secret)

    copy_parser = subparsers.add_parser("copy",
                                        description="Copy the secret to clipboard.",
                                        help="copy the secret to clipboard")
    copy_parser.add_argument("name", help="name of the secret")
    add_index_argument(copy_parser)
    copy_parser.set_defaults(command=copy_secret)

    args = parser.parse_args()
    args.command(args)
