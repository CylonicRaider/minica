#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import subprocess

OPENSSL_PATH = '/usr/bin/openssl'

def split_pem_objects(lines):
    output = []
    cur_accum = None
    for n, line in enumerate(lines, 1):
        if line.startswith('-----BEGIN '):
            if not line.endswith('-----'):
                raise ValueError('Invalid pre-encapsulation boundary on '
                                 'line ' + str(n))
            elif cur_accum:
                raise ValueError('Unexpected pre-encapsulation boundary on '
                                 'line ' + str(n))
            cur_accum = [line[11:-5], []]
        elif line.startswith('-----END '):
            if not line.endswith('-----'):
                raise ValueError('Invalid post-encapsulation boundary on '
                                 'line ' + str(n))
            elif not cur_accum:
                raise ValueError('Unexpected post-encapsulation boundary on '
                                 'line ' + str(n))
            output.append((cur_accum[0], '\n'.join(cur_accum[1])))
            cur_accum = None
        elif line.startswith('-----'):
            raise ValueError('Invalid non-boundary line ' + str(n))
        elif cur_accum:
            cur_accum[1].append(line)
    if cur_accum:
        raise ValueError('Missing final post-encapsulation boundary')
    return output

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
