#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import os, re
import stat
import subprocess

VALID_NAME = re.compile('^[a-zA-Z0-9._-]+$')

OPENSSL_PATH = '/usr/bin/openssl'
DEFAULT_NEW_KEY_SPEC = 'rsa:4096'
DEFAULT_NEW_CERT_VALIDITY = 30 # days

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
        self.new_key_spec = DEFAULT_NEW_KEY_SPEC
        self.new_cert_validity = DEFAULT_NEW_CERT_VALIDITY

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

    def _create_cert(self, cmdline, key_path, cert_path):
        res = None
        try:
            res = self._run_openssl(cmdline)
        finally:
            if not res or res['status'] != 0:
                if key_path: self._silent_remove(key_path)
                if cert_path: self._silent_remove(cert_path)
        if res['status'] != 0:
            return {'status': 'FAIL', 'detail': res['stderr']}
        ret = {'status': 'OK'}
        if key_path: ret['key_path'] = key_path
        if cert_path: ret['cert_path'] = cert_path
        return ret

    def create_root(self, basename):
        if not VALID_NAME.match(basename):
            raise ValueError('Invalid certificate basename')
        key_path = os.path.join(self.storage_dir, 'key', basename + '.pem')
        cert_path = os.path.join(self.storage_dir, 'cert', basename + '.pem')
        return self._create_cert((
            # Generate self-signed certificate.
            'req', '-x509',
            # Unencrypted private key.
            '-nodes',
            # Generate a new key.
            '-newkey', self.new_key_spec,
            # Do not prompt for a subject.
            '-subj', '/O=Local/CN=' + basename,
            # Write certificate and key to files.
            '-keyout', key_path, '-out', cert_path
        ), key_path, cert_path)

def main():
    raise NotImplementedError

if __name__ == '__main__': main()
