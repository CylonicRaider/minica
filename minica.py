#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import os, re
import random
import stat
import subprocess
import shutil

VALID_NAME = re.compile('^[a-zA-Z0-9._-]+$')
ISSUER_LINE = re.compile('^issuer\s*=\s*(/[^\n]*)$')

ORGANIZATION = 'Local'
UNIT_ROOT = 'Root'
UNIT_INTERMEDIATE = 'Intermediate'
UNIT_LEAF = 'Leaf'

OPENSSL_PATH = '/usr/bin/openssl'

STORAGE_DIR = '/etc/minica'
DEFAULT_NEW_KEY_SPEC = 'rsa:4096'
DEFAULT_NEW_CERT_HASH = 'sha256'
DEFAULT_NEW_CERT_DAYS = 30

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

class Error(Exception): pass

class ParsingError(Error): pass

class FileParsingError(ParsingError):
    def __init__(self, file, line, message):
        super().__init__('{}:{}: {}'.format(file, line, message))
        self.file = file
        self.line = line
        self.messsage = message

class ValidationError(Error): pass

class ExecutionError(Error):
    def __init__(self, summary, status=None, detail=None):
        super().__init__('{}{}{}'.format(summary, ('\n' if detail else ''),
                                         detail or '')
        self.summary = summary
        self.status = status
        self.detail = detail

def parse_rdn(data):
    items = data.split('/')
    if not items or items[0]:
        raise ParsingError('RDN does not start with a slash')
    output = []
    for item in items:
        name, sep, value = item.partition('=')
        if not sep:
            raise ParsingError(
                'RDN component does not contain an equals sign')
        output.append((name, value))
    return tuple(output)

def split_pem_objects(lines, filename='<input>'):
    output = []
    cur_accum = None
    n = 0
    for n, line in enumerate(lines, 1):
        if line.startswith('-----BEGIN '):
            if not line.endswith('-----'):
                raise FileParsingError(filename, n,
                    'Invalid pre-encapsulation boundary')
            elif cur_accum:
                raise FileParsingError(filename, n,
                    'Unexpected pre-encapsulation boundary')
            cur_accum = [line[11:-5], []]
        elif line.startswith('-----END '):
            if not line.endswith('-----'):
                raise FileParsingError(filename, n,
                    'Invalid post-encapsulation boundary')
            elif not cur_accum:
                raise FileParsingError(filename, n,
                    'Unexpected post-encapsulation boundary')
            elif line[9:-5] != cur_accum[0]:
                raise FileParsingError(filename, n,
                    'Post-encapsulation boundary does not match previous '
                    'pre-encapsulation boundary')
            output.append((cur_accum[0], '\n'.join(cur_accum[1])))
            cur_accum = None
        elif line.startswith('-----'):
            raise FileParsingError(filename, n, 'Invalid boundary-like line')
        elif cur_accum:
            cur_accum[1].append(line)
    if cur_accum:
        raise FileParsingError(filename, n + 1,
            'Missing final post-encapsulation boundary')
    return output

class OpenSSLDriver:
    def __init__(self, openssl_path=None, storage_dir=None, new_key_spec=None,
                 new_cert_fingerprint=None, new_cert_validity=None):
        if openssl_path is None: openssl_path = OPENSSL_PATH
        if storage_dir is None: storage_dir = STORAGE_DIR
        if new_key_spec is None: new_key_spec = DEFAULT_NEW_KEY_SPEC
        if new_cert_hash is None: new_cert_hash = DEFAULT_NEW_CERT_HASH
        if new_cert_days is None: new_cert_days = DEFAULT_NEW_CERT_DAYS
        self.openssl_path = openssl_path
        self.storage_dir = storage_dir
        self.new_key_spec = new_key_spec
        self.new_cert_hash = new_cert_hash
        self.new_cert_days = new_cert_days
        self.random = random.SystemRandom()

    def _run_openssl(self, args, input=None, require_status=0):
        proc = subprocess.Popen((self.openssl_path,) + tuple(args),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input)
        status = proc.wait()
        if require_status is not None and status != require_status:
            raise ExecutionError('openssl exited with unexpected status {}'
                                 .format(status), status, stderr)
        return {'status': status, 'stdout': stdout, 'stderr': stderr}

    def _write_and_adjust(self, source, destination, mode, owner, group):
        with open(destination, 'w') as df:
            os.chmod(df.fileno(), mode)
            shutil.chown(df.fileno(), owner, group)
            for block in source:
                df.write(block)

    def _copy_and_adjust(self, source, destination, mode, owner, group):
        with open(source) as sf:
            self._write_and_adjust(iter(lambda: sf.read(4096), ''),
                                   destination, mode, owner, group)

    def _silent_remove(self, path):
        try:
            os.remove(path)
        except OSError:
            pass

    def _derive_paths(self, basename, detail=None):
        if not VALID_NAME.match(basename):
            raise ValueError('Invalid {}certificate basename'
                             .format(detail + ' ' if detail else ''))
        return (os.path.join(self.storage_dir, 'cert', basename + '.pem'),
                os.path.join(self.storage_dir, 'key', basename + '.pem'))

    def _get_issuser_basename(self, filename=None, input=None):
        if filename is not None and input is not None:
            raise RuntimeError('_get_issuser_basename() got redundant file '
                               'name and data')
        cmdline = (
            # Parse certificate.
            'x509',
            # Do not output it again.
            '-noout',
            # Print out the issuer.
            '-issuer'
        )
        if filename is not None:
            # Read input from the given file.
            cmdline += ('-in', filename)
        res = self._run_openssl(cmdline, input)
        m = ISSUER_LINE.match(res['stdout'])
        if not m:
            raise ExecutionError(
                'openssl returned invalid certificate issuer line',
                res['status'], res['stderr'])
        rdn_parts = parse_rdn(m.group(1))
        if (len(rdn_parts) != 3 or
                rdn_parts[0] != ('O', ORGANIZATION) or
                rdn_parts[1] not in (('OU', UNIT_ROOT),
                                     ('OU', UNIT_INTERMEDIATE)) or
                rdn_parts[2][0] != 'CN'):
            raise ValidationError('Invalid certificate issuer RDN')
        basename = parts[2][1]
        if not VALID_NAME.match(basename):
            raise ValidationError('Invalid issuer certificate basename')
        return basename

    def _collect_chain(self, leaf_basename):
        output = []
        cur_basename = leaf_basename
        while 1:
            cur_path = self._derive_paths(cur_basename)[0]
            with open(cur_path) as f:
                cur_data = f.read()
            output.append((cur_basename, cur_data))
            cur_parent = self._get_issuer_basename(input=cur_data)
            if cur_parent == cur_basename: break
            cur_basename = cur_parent
        return output

    def _create_cert(self, cmdline, cert_path, key_path, input=None):
        res = None
        try:
            res = self._run_openssl(cmdline, input)
            ret = {'status': 'OK'}
            if cert_path:
                os.chmod(cert_path, 0o444)
                ret['cert_path'] = cert_path
            if key_path:
                os.chmod(key_path, 0o400)
                ret['key_path'] = key_path
        finally:
            if not res:
                if cert_path: self._silent_remove(cert_path)
                if key_path: self._silent_remove(key_path)
        return ret

    def prepare_storage(self, replace=False):
        os.makedirs(self.storage_dir)
        cert_dir = os.path.join(self.storage_dir, 'cert')
        os.mkdir(cert_dir)
        os.chmod(cert_dir, 0o755)
        key_dir = os.path.join(self.storage_dir, 'key')
        os.mkdir(key_dir)
        os.chmod(key_dir, 0o700)
        ext_file = os.path.join(self.storage_dir, 'extensions.cnf')
        if replace or not os.path.exists(ext_file):
            with open(ext_file, 'w') as f:
                f.write(DEFAULT_EXTENSIONS)

    def create_root(self, basename):
        cert_path, key_path = self._derive_paths(basename)
        if os.path.exists(cert_path):
            raise ValidationError('New certificate basename already in use')
        return self._create_cert((
            # Generate self-signed certificate.
            'req', '-x509',
            # Unencrypted private key.
            '-nodes',
            # Use the given fingerprint.
            '-' + self.new_cert_hash,
            # Generate a new key.
            '-newkey', self.new_key_spec,
            # Do not prompt for a subject.
            '-subj', '/O={}/OU={}/CN={}'.format(ORGANIZATION, UNIT_ROOT,
                                                basename),
            # Not-that-serial number.
            '-set_serial', str(self.random.getrandbits(20 * 8 - 1)),
            # Use the configured validity interval.
            '-days', self.new_cert_days,
            # Write certificate and key to files.
            '-out', cert_path, '-keyout', key_path
        ), cert_path, key_path)

    def _create_derived(self, new_basename, parent_basename, ca):
        new_cert_path, new_key_path = self._derive_paths(new_basename,
                                                         'new')
        par_cert_path, par_key_path = self._derive_paths(parent_basename,
                                                         'parent')
        if os.path.exists(new_cert_path):
            raise ValidationError('New certificate basename already in use')
        success = False
        try:
            res_request = self._run_openssl((
                # Generate certificate request.
                'req',
                # Unencrypted private key.
                '-nodes',
                # Use the given fingerprint.
                '-' + self.new_cert_hash,
                # Generate a new key.
                '-newkey', self.new_key_spec,
                # Do not prompt a subject.
                '-subj', '/O={}/OU={}/CN={}'.format(ORGANIZATION,
                    (UNIT_INTERMEDIATE if ca else UNIT_LEAF), basename),
                # Write the key to its final location but the request to
                # standard output.
                '-keyout', new_key_path
            ))
            ext_file = os.path.join(self.storage_dir, 'extensions.cnf')
            return self._create_cert((
                # Sign a certificate request.
                'x509', '-req',
                # Use the configured validity interval.
                '-days', self.new_cert_days,
                # Who needs *serial* numbers, anyway?
                '-set_serial', str(self.random.getrandbits(20 * 8 - 1)),
                # Add appropriate extensions.
                '-extfile', ext_file,
                '-extensions', ('ext_ca' if ca else 'ext_leaf'),
                # Use the given CA.
                '-CA', par_cert_path, '-CAkey', par_key_path,
                # Output the finished certificate to the correct location.
                '-out', new_cert_path
            ), new_cert_path, new_key_path, res_request['stdout'])
        finally:
            if not success:
                self._silent_remove(new_cert_path)
                self._silent_remove(new_key_path)

    def create_intermediate(self, new_basename, parent_basename):
        return self._create_derived(new_basename, parent_basename, True)

    def create_leaf(self, new_basename, parent_basename):
        return self._create_derived(new_basename, parent_basename, False)

    def remove(self, basename):
        cert_path, key_path = self._derive_paths(basename)
        self._silent_remove(cert_path)
        self._silent_remove(key_path)

    def export(self, basename, cert_dest, chain_dest, root_dest, key_dest,
               new_owner, new_group):
        cert_path, key_path = self._derive_paths(basename)
        chain = self._collect_chain(basename)
        cert_written = chain_written = root_written = key_written = False
        ok = True
        try:
            self._write_and_adjust((chain[0][1],), cert_dest, 0o444,
                                   new_owner, new_group)
            cert_written = True
            if chain_dest is not None:
                self._write_and_adjust((p[1] for p in chain[1:-1]),
                                       chain_dest, 0o444,
                                       new_owner, new_group)
                chain_written = True
            if root_dest is not None:
                self._write_and_adjust((chain[-1][1],), 0o444,
                                       new_owner, new_group)
                root_written = True
            if key_dest is not None:
                self._copy_and_adjust(key_path, key_dest, 0o400,
                                      new_owner, new_group)
                key_written = True
            ok = True
        finally:
            if not ok:
                if cert_written: self._silent_remove(cert_dest)
                if chain_written: self._silent_remove(chain_dest)
                if root_written: self._silent_remove(root_dest)
                if key_written: self._silent_remove(key_dest)

def main():
    raise NotImplementedError

if __name__ == '__main__': main()
