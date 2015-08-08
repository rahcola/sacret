#!/usr/bin/env python

import argparse
import json
import os.path
import subprocess
import getpass


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
            raise RuntimeError(pw_err.decode("utf-8"))
        raise RuntimeError(text_err.decode("utf-8"))
    return text.decode("utf-8")

def read_index(index_path, password_path):
    return json.loads(read_encrypted(index_path, password_path))

def read_secret(index_path, password_path, name):
    entry = read_index(index_path, password_path)[name]
    return read_encrypted(entry["path"],
                          entry["password"] if "password" in entry
                          else password_path)

def init_secrets(args):
    if os.path.exists(args.index):
        raise ValueError("index file {} exists".format(args.index))
    if os.path.exists(args.password):
        raise ValueError("password file {} exists".format(args.password))
    password = getpass.getpass("index password: ")
    epw_p = subprocess.Popen(["gpg", "-e", "-a", "--output", args.password],
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    epw_err = epw_p.communicate(password.encode("utf-8"))[1]
    if epw_p.returncode > 0:
        raise RuntimeError(epw_err.decode("utf-8"))
    pw_p = subprocess.Popen(["gpg", "-d", args.password],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    e_p = subprocess.Popen(["gpg", "-a", "--symmetric", "--batch",
                            "--passphrase-fd", str(pw_p.stdout.fileno()),
                            "--output", args.index],
                           stdin=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           pass_fds=[pw_p.stdout.fileno()])
    pw_p.stdout.close()
    e_p.stdin.write("{}\n".encode("utf-8"))
    e_p.stdin.close()
    pw_err = b""
    e_err = b""
    while pw_p.poll() is None or e_p.poll() is None:
        pw_err += pw_p.stderr.read()
        e_err += e_p.stderr.read()
    if e_p.returncode > 0:
        if pw_p.returncode > 0:
            raise RuntimeError(pw_err.decode("utf-8"))
        raise RuntimeError(e_err.decode("utf-8"))

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
                        default=os.path.expanduser("~/.sacret/index.asc"),
                        metavar="<path>")

def add_password_argument(parser):
    parser.add_argument("-p", "--password",
                        help="encrypted password file for index",
                        default=os.path.expanduser("~/.sacret/index_password.asc"),
                        metavar="<path>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plain file secret manager.")
    parser.set_defaults(command=lambda args: parser.print_help())
    subparsers = parser.add_subparsers(description=None, metavar="<command>")

    init_parser = subparsers.add_parser("init",
                                        description="Create an index of secrets.",
                                        help="create an index of secrets")
    add_index_argument(init_parser)
    add_password_argument(init_parser)
    init_parser.set_defaults(command=init_secrets)

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
