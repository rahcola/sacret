#!/usr/bin/env python

import argparse
import json
import subprocess
import sys

def list_secrets(args):
    pw_p = subprocess.Popen(["gpg", "-d", args.password],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    index_p = subprocess.Popen(["gpg", "--batch", "--passphrase-fd", "0",
                                "-d", args.index],
                               stdin=pw_p.stdout,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    pw_p.stdout.close()
    pw_err = b""
    index_err = b""
    index = ""
    while pw_p.poll() is None or index_p.poll() is None:
        pw_err += pw_p.stderr.read()
        index_err += index_p.stderr.read()
        index += index_p.stdout.read().decode("utf-8")
    if index_p.returncode > 0:
        if pw_p.returncode > 0:
            sys.stderr.buffer.write(pw_err)
        sys.stderr.buffer.write(index_err)
    print("\n".join(json.loads(index).keys()))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plain file secret manager.")
    subparsers = parser.add_subparsers(metavar="<command>")

    list_parser = subparsers.add_parser("list",
                                        description="List the names of the secrets.",
                                        help="list the names of the secrets")
    list_parser.set_defaults(command=list_secrets)
    list_parser.add_argument("-i", "--index",
                             help="encrypted index of secrets",
                             default="~/.sacret/index.asc",
                             metavar="<path>")
    list_parser.add_argument("-p", "--password",
                             help="encrypted password file",
                             default="~/.sacret/password.asc",
                             metavar="<path>")
    args = parser.parse_args()
    args.command(args)
