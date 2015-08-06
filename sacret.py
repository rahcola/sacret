#!/usr/bin/env python

import argparse
import json
import subprocess

class CannotReadEncrypted(Exception):
    pass

def read_encrypted(path, password_path):
    pw_p = subprocess.Popen(["gpg", "-d", password_path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    text_p = subprocess.Popen(["gpg", "--batch", "--passphrase-fd", "0",
                               "-d", path],
                              stdin=pw_p.stdout,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    pw_p.stdout.close()
    pw_err = b""
    text_err = b""
    text = b""
    while pw_p.poll() is None or text_p.poll() is None:
        pw_err += pw_p.stderr.read()
        text_err += text_p.stderr.read()
        text += text_p.stdout.read()
    if text_p.returncode > 0:
        if pw_p.returncode > 0:
            raise CannotReadEncrypted(pw_err.decode("utf-8"))
        raise CannotReadEncrypted(text_err.decode("utf-8"))
    return text.decode("utf-8")

def read_index(index_path, password_path):
    return json.loads(read_encrypted(index_path, password_path))

def read_secret(index_path, password_path, name):
    entry = read_index(index_path, password_path)[name]
    return read_encrypted(entry["path"],
                          entry["password"] if "password" in entry
                          else password_path)

def list_secrets(args):
    print("\n".join(read_index(args.index, args.password).keys()))

def show_secret(args):
    print(read_secret(args.index, args.password, args.name), end="")

def copy_secret(args):
    secret = read_secret(args.index, args.password, args.name).splitlines()[0]
    p = subprocess.Popen(["xclip", "-selection", "clipboard"],
                         stdin=subprocess.PIPE)
    p.communicate(secret.encode("utf-8"))

def add_index_argument(parser):
    parser.add_argument("-i", "--index",
                        help="encrypted index of secrets",
                        default="~/.sacret/index.asc",
                        metavar="<path>")

def add_password_argument(parser):
    parser.add_argument("-p", "--password",
                        help="encrypted password file for index",
                        default="~/.sacret/index_password.asc",
                        metavar="<path>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plain file secret manager.")
    parser.set_defaults(command=lambda args: parser.print_help())
    subparsers = parser.add_subparsers(description=None, metavar="<command>")

    list_parser = subparsers.add_parser("list",
                                        description="List the names of the secrets.",
                                        help="list the names of the secrets")
    add_index_argument(list_parser)
    add_password_argument(list_parser)
    list_parser.set_defaults(command=list_secrets)

    show_parser = subparsers.add_parser("show",
                                        description="Show the secret.",
                                        help="show the secret")
    show_parser.add_argument("name", help="name of the secret")
    add_index_argument(show_parser)
    add_password_argument(show_parser)
    show_parser.set_defaults(command=show_secret)

    copy_parser = subparsers.add_parser("copy",
                                        description="Copy the secret to clipboard.",
                                        help="copy the secret to clipboard")
    copy_parser.add_argument("name", help="name of the secret")
    add_index_argument(copy_parser)
    add_password_argument(copy_parser)
    copy_parser.set_defaults(command=copy_secret)

    args = parser.parse_args()
    args.command(args)
