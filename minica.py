#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import os
import stat
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
            elif line[9:-5] != cur_accum[0]:
                raise ValueError('Post-encapsulation boundary on line ' +
                    str(n) + ' does not match pre-encapsulation boundary')
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
    def __init__(self, storage_dir):
        self.storage_dir = storage_dir
        self.openssl_path = OPENSSL_PATH

    def _run_openssl(self, args, input=None):
        proc = subprocess.Popen((self.openssl_path,) + tuple(args),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input)
        status = proc.wait()
        return {'status': status, 'stdout': stdout, 'stderr': stderr}

    def _silent_remove(self, path):
        try:
            os.remove(path)
        except OSError:
            pass

    def prepare_storage(self):
        os.makedirs(self.storage_dir)
        os.chmod(self.storage_dir, 0o755)
        key_dir = os.path.join(self.storage_dir, 'key')
        os.mkdir(key_dir)
        os.chmod(key_dir, 0o700)
        cert_dir = os.path.join(self.storage_dir, 'cert')
        os.mkdir(cert_dir)
        os.chmod(cert_dir, 0o755)

def main():
    raise NotImplementedError

if __name__ == '__main__': main()
