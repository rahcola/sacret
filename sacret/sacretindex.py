#!/usr/bin/env python
"""Usage:
  sacretindex.py (init | list) [--index <path>]
  sacretindex.py get [--index <path>] <key>
  sacretindex.py add [--index <path>] <key> <value>
  sacretindex.py (-h | --help | -v | --version)

Options:
  -i <path> --index <path>  Secret index. [default: ./index.asc]
  -h --help                 Show this help.
  -v --version              Show version.

"""
from docopt import docopt
import os
import os.path
import pytoml
import subprocess
import sys


decrypt = ['gpg', '-q', '--batch', '-d']
encrypt = ['gpg', '-q', '--batch', '-a', '--symmetric']

def init(index_path):
    with open(os.devnull) as devnull:
        subprocess.check_call(encrypt + ['--output', index_path], stdin=devnull)

def list_keys(index_path):
    index = subprocess.check_output(decrypt + [index_path])
    return list(pytoml.loads(index).keys())

def get(index_path, key):
    index = subprocess.check_output(decrypt + [index_path])
    return pytoml.loads(index)[key]

def add(index_path, key, value):
    index = pytoml.loads(subprocess.check_output(decrypt + [index_path]))
    if key not in index:
        index[key] = value
        cmd = encrypt + ['--yes', '--output', index_path]
        with subprocess.Popen(cmd,
                              stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True) as gpg:
            err = gpg.communicate(pytoml.dumps(index))[1].encode()
            if gpg.wait() != 0:
                raise subprocess.CalledProcessError(gpg.poll(), cmd, err)

def parse_command(arguments, actions):
    for command in actions:
        if arguments[command]:
            return actions[command]

if __name__ == '__main__':
    arguments = docopt(__doc__, version='sacretindex.py 0.0.2')
    actions = {
        'init': lambda args: init(args['--index']),
        'list': lambda args: print('\n'.join(list_keys(args['--index']))),
        'get': lambda args: print(get(args['--index'], args['<key>'])),
        'add': lambda args: add(args['--index'], args['<key>'], args['<value>'])
    }
    arguments['--index'] = os.path.expanduser(arguments['--index'])
    try:
        parse_command(arguments, actions)(arguments)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output.decode())
        sys.exit(e.returncode)
