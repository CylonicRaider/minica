#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import os, re
import random
import stat
import subprocess

VALID_NAME = re.compile('^[a-zA-Z0-9._-]+$')

OPENSSL_PATH = '/usr/bin/openssl'

DEFAULT_NEW_KEY_SPEC = 'rsa:4096'
DEFAULT_NEW_CERT_FINGERPRINT = 'sha256'
DEFAULT_NEW_CERT_VALIDITY = 30 # days

DEFAULT_EXTENSIONS = '''
# X.509 extension definition file.
# Do not rename the "ext_ca" and "ext_leaf" sections!

[ext_ca]
basicConstraints = critical,CA:TRUE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ext_leaf]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
'''[1:]

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
        self.new_cert_fingerprint = DEFAULT_NEW_CERT_FINGERPRINT
        self.new_cert_validity = DEFAULT_NEW_CERT_VALIDITY
        self.random = random.SystemRandom()

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

    def prepare_storage(self, replace=False):
        os.makedirs(self.storage_dir)
        os.chmod(self.storage_dir, 0o755)
        key_dir = os.path.join(self.storage_dir, 'key')
        os.mkdir(key_dir)
        os.chmod(key_dir, 0o700)
        cert_dir = os.path.join(self.storage_dir, 'cert')
        os.mkdir(cert_dir)
        os.chmod(cert_dir, 0o755)
        ext_file = os.path.join(self.storage_dir, 'extensions.cnf')
        if replace or not os.path.exists(ext_file):
            with open(ext_file, 'w') as f:
                f.write(DEFAULT_EXTENSIONS)

    def _derive_paths(self, basename, detail=None):
        if not VALID_NAME.match(basename):
            raise ValueError('Invalid {}certificate basename'
                             .format(detail + ' ' if detail else ''))
        return (os.path.join(self.storage_dir, 'key', basename + '.pem'),
                os.path.join(self.storage_dir, 'cert', basename + '.pem'))

    def _create_cert(self, cmdline, key_path, cert_path, input=None):
        res = None
        try:
            res = self._run_openssl(cmdline, input)
            if res['status'] != 0:
                return {'status': 'FAIL', 'detail': res['stderr']}
            ret = {'status': 'OK'}
            if key_path:
                os.chmod(key_path, 0o400)
                ret['key_path'] = key_path
            if cert_path:
                os.chmod(cert_path, 0o444)
                ret['cert_path'] = cert_path
        finally:
            if not res or res['status'] != 0:
                if key_path: self._silent_remove(key_path)
                if cert_path: self._silent_remove(cert_path)
        return ret

    def create_root(self, basename):
        key_path, cert_path = self._derive_paths(basename)
        if os.path.exists(cert_path):
            raise ValueError('New certificate basename already in use')
        return self._create_cert((
            # Generate self-signed certificate.
            'req', '-x509',
            # Unencrypted private key.
            '-nodes',
            # Use the given fingerprint.
            '-' + self.new_cert_fingerprint,
            # Generate a new key.
            '-newkey', self.new_key_spec,
            # Do not prompt for a subject.
            '-subj', '/O=Local/OU=Root/CN=' + basename,
            # Not-that-serial number.
            '-set_serial', str(self.random.getrandbits(20 * 8 - 1)),
            # Use the configured validity interval.
            '-days', self.new_cert_validity,
            # Write certificate and key to files.
            '-keyout', key_path, '-out', cert_path
        ), key_path, cert_path)

    def _create_derived(self, new_basename, parent_basename, ca):
        new_key_path, new_cert_path = self._derive_paths(new_basename,
                                                         'new')
        par_key_path, par_cert_path = self._derive_paths(parent_basename,
                                                         'parent')
        if os.path.exists(new_cert_path):
            raise ValueError('New certificate basename already in use')
        success = False
        try:
            res_request = self._run_openssl((
                # Generate certificate request.
                'req',
                # Unencrypted private key.
                '-nodes',
                # Use the given fingerprint.
                '-' + self.new_cert_fingerprint,
                # Generate a new key.
                '-newkey', self.new_key_spec,
                # Do not prompt a subject.
                '-subj', '/O=Local/OU={}/CN={}'.format(
                    ('Intermediate' if ca else 'Leaf'), basename),
                # Write the key to its final location but the request to
                # standard output.
                '-keyout', new_key_path
            ))
            if res_request['status'] != 0:
                return {'status': 'FAIL', 'detail': res_request['stderr']}
            ext_file = os.path.join(self.storage_dir, 'extensions.cnf')
            return self._create_cert((
                # Sign a certificate request.
                'x509', '-req',
                # Use the given configuration file.
                '-config', ext_file,
                # Use the configured validity interval.
                '-days', self.new_cert_validity,
                # Who needs *serial* numbers, anyway?
                '-set_serial', str(self.random.getrandbits(20 * 8 - 1)),
                # Add appropriate extensions.
                '-extensions', ('ext_ca' if ca else 'ext_leaf'),
                # Use the given CA.
                '-CA', par_cert_path, '-CAkey', par_key_path,
                # Output the finished certificate to the correct location.
                '-out', new_cert_path
            ), new_key_path, new_cert_path, res_request['stdout'])
        finally:
            if not success:
                self._silent_remove(new_key_path)
                self._silent_remove(new_cert_path)

    def create_intermediate(self, new_basename, parent_basename):
        return self._create_derived(new_basename, parent_basename, True)

    def create_leaf(self, new_basename, parent_basename):
        return self._create_derived(new_basename, parent_basename, False)

    def remove(self, basename):
        key_path, cert_path = self._derive_paths(basename)
        self._silent_remove(key_path)
        self._silent_remove(cert_path)

def main():
    raise NotImplementedError

if __name__ == '__main__': main()
