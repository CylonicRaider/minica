#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import subprocess

OPENSSL_PATH = '/usr/bin/openssl'

class OpenSSLDriver:
    def __init__(self):
        self.openssl_path = OPENSSL_PATH

    def _run_openssl(self, args, input):
        proc = subprocess.Popen((self.openssl_path,) + tuple(args),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdin, stdout = proc.communicate(input)
        status = proc.wait()
        return {'status': status, 'stdin': stdin, 'stdout': stdout}

def main():
    raise NotImplementedError

if __name__ == '__main__': main()
