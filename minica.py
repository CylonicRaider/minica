#!/usr/bin/env python3
# -*- coding: ascii -*-

"""
Simple local X.509 certificate management.
"""

import sys, os, re, time
import random
import stat
import calendar, datetime
import subprocess
import shutil, shlex
import argparse
import email.utils

VALID_NAME = re.compile(r'\A[a-zA-Z0-9._-]+\Z')

ORGANIZATION = 'Local'
UNIT_ROOT = 'Root'
UNIT_INTERMEDIATE = 'Intermediate'
UNIT_LEAF = 'Leaf'

OPENSSL_PATH = '/usr/bin/openssl'
STORAGE_DIR = '/etc/minica'
USER_STORAGE_DIR = '~/.minica'

DEFAULT_NEW_KEY_SPEC = 'rsa:4096'
DEFAULT_NEW_CERT_HASH = 'sha256'
DEFAULT_NEW_CERT_DAYS = 30

PARSE_LINE = re.compile(r'\A([a-zA-Z0-9]+)\s*=\s*(.*)\Z')
DAYS_IN_TOKEN = re.compile(r'([+-]?[1-9][0-9]*)([dwmyDWMY])')
DAYS_IN_PATTERN = re.compile(
    r'\A(?:[+-]?[1-9][0-9]*[dwmyDWMY]\s*)*(?:[+-]?[1-9][0-9]*[dwmyDWMY])\Z')
WHITESPACE = re.compile(r'\s+')

class Error(Exception):
    """
    Base class for exceptions raised by this module.
    """

class InputError(Error):
    """
    Exception raised to indicate generic problems with some input.
    """

class ParsingError(InputError):
    """
    Exception raised when an input could not be parsed.
    """

class ValidationError(Error):
    """
    Exception raised when something failed validation.
    """

class ExecutionError(Error):
    """
    ExecutionError(summary, status=None, detail=None) -> new instance

    Exception raised when an external command failed.

    summary is a textual message summarizing the error.

    status is an integer containing the command's exit status code (if
    available).

    detail contains additional information as a string (such as a standard
    error dump), or None if not available.

    The string representation of an instance consists of summary followed by
    detail (with None interpreted as the empty string), separated by a newline
    if detail is not empty.
    """

    def __init__(self, summary, status=None, detail=None):
        "Instance initializer; see the class docstring for details."
        super().__init__('{}{}{}'.format(summary, ('\n' if detail else ''),
                                         detail or ''))
        self.summary = summary
        self.status = status
        self.detail = detail

def parse_rdn(text):
    """
    Parse an RDN (Relative Distinguished Name) into a list of type-name pairs.

    This expects text to be formatted as done by default by openssl-x509, i.e.
        /TYPE1=name1/TYPE2=name2/TYPE3=name3/...
    Whitespace is significant. Multi-valued RDNs are not supported. The parse
    result is returned.
    """
    items = text.split('/')
    if not items or items[0]:
        raise ParsingError('RDN does not start with a slash')
    output = []
    for item in items[1:]:
        name, sep, value = item.partition('=')
        if not sep:
            raise ParsingError(
                'RDN component does not contain an equals sign')
        output.append((name, value))
    return tuple(output)

def parse_days_in(spec, base=None):
    """
    Parse an extended days-in specification.

    The specification (spec) consists of "duration tokens" with optional
    intervening whitespace. A duration token consists of a (positive or
    negative) integer followed immediately by a time unit letter, one of
    "d"/"w"/"m"/"y", meaning "days"/"weeks"/"months"/"years", respectively.

    base is the base date to apply the algorithm to, as a datetime.date
    instance, defaulting to today.

    The parsing algorithm takes each duration token individually in the order
    given and shifts the current date (initialized from the base date) by the
    amount denoted by the token (with positive amounts shifting into the
    future). If the day-of-month is out of range after applying a "months" or
    "years" token, it is clamped into range, keeping the year and month the
    unchanged.

    For example, applying the days-in string "1y 2m" to the date 2000-02-29
    results in the date 2001-04-28; in contrast, applying the string "2m 1y"
    to 2000-02-29 results in 2001-04-29.

    Returns the appropriately shifted base date as a datetime.date instance.
    """
    if not DAYS_IN_PATTERN.match(spec):
        raise ValueError('Invalid days-in specification: {}'.format(spec))
    cur = datetime.date.today() if base is None else base
    index = 0
    while 1:
        m = WHITESPACE.match(spec, index)
        if m: index = m.end()
        m = DAYS_IN_TOKEN.match(spec, index)
        if not m: break
        index = m.end()
        count = int(m.group(1))
        unit = m.group(2).lower()
        if unit == 'd':
            cur += datetime.timedelta(days=count)
        elif unit == 'w':
            cur += datetime.timedelta(weeks=count)
        elif unit == 'm':
            # Yay for lacking functionality!
            new_month_idx = cur.year * 12 + (cur.month - 1) + count
            new_year, new_month = divmod(new_month_idx, 12)
            new_month += 1
            new_month_len = calendar.monthrange(new_year, new_month)[1]
            new_day = min(cur.day, new_month_len)
            cur = datetime.date(new_year, new_month, new_day)
        elif unit == 'y':
            new_year, new_month = cur.year + count, cur.month
            new_month_len = calendar.monthrange(new_year, new_month)[1]
            new_day = min(cur.day, new_month_len)
            cur = datetime.date(new_year, new_month, new_day)
        else:
            raise AssertionError('This should not happen!')
    if index < len(spec):
        # This *should* not happen.
        raise ValueError('Invalid days-in specification (has trailing '
            'junk): {}'.format(spec))
    return cur

def format_shell_line(*argv):
    """
    Helper: Format the given arguments as a shell command line.

    This is *only* used for the dry-run mode.
    """
    return ' '.join(shlex.quote(a) for a in argv)

class MiniCA:
    """
    MiniCA(openssl_path=None, storage_dir=None, new_key_spec=None,
        new_cert_hash=None, new_cert_days=None, **kwargs) -> new instance

    Certificate manager backed by the OpenSSL command-line interface.

    The constructor arguments specify various configuration values; most of
    them they default to similarly-named module-level constants:
    openssl_path : Where the OpenSSL CLI binary is located. (OPEENSSL_PATH)
    storage_dir  : Where the certificate and key store should be located,
                   as a filesystem path. (STORAGE_DIR)
    new_key_spec : How new private keys should be constructed.
                   (DEFAULT_NEW_KEY_SPEC)
    new_cert_hash: The cryptographic hash function to be used for new
                   certificate signatures. (DEFAULT_NEW_CERT_HASH)
    new_cert_days: How long a new certificate should be valid, in days, as an
                   integer. (DEFAULT_NEW_CERT_DAYS)
    dry_run      : Instead of performing actions, print equivalent shell
                   commands. (Defaults to False.)
    The arguments (after default value substitution) are stored as same-named
    instance attributes.

    Most of the instance methods assume that the certificate store has been
    initialized using the prepare_storage() method beforehand.
    """

    def __init__(self, openssl_path=None, storage_dir=None, new_key_spec=None,
                 new_cert_hash=None, new_cert_days=None, dry_run=False):
        "Instance initializer; see the class docstring for details."
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
        self.dry_run = dry_run
        self.random = random.SystemRandom()

    def _run_openssl(self, args, input=None, require_status=0):
        "Internal: Actually invoke the OpenSSL CLI."
        full_args = (self.openssl_path,) + tuple(args)
        if self.dry_run:
            print(format_shell_line(*full_args))
            return
        proc = subprocess.Popen(full_args,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)
        stdout, stderr = proc.communicate(input)
        status = proc.wait()
        if require_status is not None and status != require_status:
            raise ExecutionError('openssl exited with unexpected status {}'
                                 .format(status), status, stderr)
        return {'status': status, 'stdout': stdout, 'stderr': stderr}

    def _drlog_name_file(self, fp):
        "Internal: Convert a thing that denotes a file into a string name."
        if isinstance(fp, str):
            return fp
        elif isinstance(fp.name, int):
            return '/dev/fd/{}'.format(fp.name)
        else:
            return str(fp.name)

    def _drlog_copy(self, source, destination):
        "Internal: Produce a dry-run log of copying source to destination."
        source_name = self._drlog_name_file(source)
        dest_name = self._drlog_name_file(destination)
        print(format_shell_line('cp', source_name, dest_name))

    def _drlog_setmode(self, location, mode, owner, group):
        "Internal: Produce a dry-run log of adjusting destination's metadata."
        loc_name = selfg._drlog_name_file(location)
        if mode is not None:
            print(format_shell_line('chmod', '{:04o}'.format(mode), loc_name))
        if owner is not None and group is not None:
            print(format_shell_line('chown', '--', '{}:{}'.format(owner,
                                                                  group),
                                    loc_name))
        elif owner is not None:
            print(format_shell_line('chown', '--', str(owner), loc_name))
        elif group is not None:
            print(format_shell_line('chgrp', '--', str(group), loc_name))

    def _write_stream(self, source, destination):
        "Internal: Write the given data to the given file"
        for block in source:
            destination.write(block)

    def _write_and_adjust(self, source, destination, mode, owner, group):
        "Internal: Write the given data to a file with specified parameters."
        if self.dry_run:
            self._drlog_copy(source, destination)
            self._drlog_setmode(destination, mode, owner, group)
            return
        if not isinstance(destination, str):
            self._write_stream(source, destination)
            return
        with open(destination, 'w') as df:
            os.chmod(df.fileno(), mode)
            if owner is not None or group is not None:
                shutil.chown(df.fileno(), owner, group)
            self._write_stream(source, df)

    def _copy_and_adjust(self, source, destination, mode, owner, group):
        "Internal: Copy the a file to a new location with given parameters."
        if self.dry_run:
            self._drlog_copy(source, destination)
            self._drlog_setmode(destination, mode, owner, group)
            return
        with open(source) as sf:
            self._write_and_adjust(iter(lambda: sf.read(4096), ''),
                                   destination, mode, owner, group)

    def _silent_remove(self, path):
        "Internal: Remove a file, ignoring errors."
        if not isinstance(path, str):
            return
        if self.dry_run:
            print(format_shell_line('rm', '-f', '--', path))
            return
        try:
            os.remove(path)
        except OSError:
            pass

    def _derive_paths(self, basename, detail=None):
        "Internal: Calculate certificate and private key paths."
        if not VALID_NAME.match(basename):
            raise ValidationError('Invalid {}certificate basename'
                                  .format(detail + ' ' if detail else ''))
        return (os.path.join(self.storage_dir, 'cert', basename + '.pem'),
                os.path.join(self.storage_dir, 'key', basename + '.pem'))

    def _get_cert_meta(self, filename=None, input=None):
        "Internal: Retrieve and parse the metadata of the named certificate."
        def decode_rdn(name):
            "Parse and validate an RDN."
            parts = parse_rdn(name)
            if (len(parts) != 3 or
                    parts[0] != ('O', ORGANIZATION) or
                    parts[1] not in (('OU', UNIT_ROOT),
                                     ('OU', UNIT_INTERMEDIATE),
                                     ('OU', UNIT_LEAF)) or
                    parts[2][0] != 'CN'):
                raise ValidationError('Invalid certificate RDN structure')
            basename = parts[2][1]
            if not VALID_NAME.match(basename):
                raise ValidationError('Invalid certificate RDN basename')
            return (parts[1][1], basename)

        def decode_timestamp(text):
            "Parse a certificate timestamp string."
            return calendar.timegm(email.utils.parsedate(text))

        if filename is not None and input is not None:
            raise RuntimeError('_get_cert_name() got redundant file '
                               'name and data')
        cmdline = (
            # Parse certificate.
            'x509',
            # Do not output it again.
            '-noout',
            # Print out the subject and issuer.
            '-subject', '-issuer',
            # ...As well as the notBefore and notAfter dates.
            '-dates'
        )
        if filename is not None:
            # Read input from the given file.
            cmdline += ('-in', filename)
        res = self._run_openssl(cmdline, input)
        raw_data = {}
        for line in res['stdout'].split('\n'):
            if not line: continue
            m = PARSE_LINE.match(line)
            if not m:
                raise ExecutionError('openssl returned invalid certificate '
                    'metadata line', res['status'], res['stderr'])
            raw_data[m.group(1)] = m.group(2)
        return {'subject': decode_rdn(raw_data['subject']),
                'issuer': decode_rdn(raw_data['issuer']),
                'notBefore': decode_timestamp(raw_data['notBefore']),
                'notAfter': decode_timestamp(raw_data['notAfter'])}

    def _collect_chain(self, leaf_basename):
        "Internal: Gather the certificate chain of the named certificate."
        output = []
        cur_basename = leaf_basename
        while 1:
            cur_path = self._derive_paths(cur_basename)[0]
            with open(cur_path) as f:
                cur_data = f.read()
            output.append((cur_basename, cur_data))
            cur_parent = self._get_cert_meta(input=cur_data)['issuer'][1]
            if cur_parent == cur_basename: break
            cur_basename = cur_parent
        return output

    def _verify_chain(self, basenames):
        "Internal: Verify a certificate chain against its root."
        if not basenames:
            return {'status': 'FAIL', 'detail': 'Certificate chain empty?!'}
        cmdline = [
            # Verify a certificate.
            'verify',
            # Using the given CA.
            '-trusted', self._derive_paths(basenames[-1], 'root')[0]
        ]
        for ibn in basenames[-2:0:-1]:
            cmdline.extend((
                # Using the given intermediate CA.
                '-untrusted', self._derive_paths(ibn, 'intermediate')[0]
            ))
        # And verify this certificate.
        cmdline.append(self._derive_paths(basenames[0], 'leaf')[0])
        res = self._run_openssl(cmdline, require_status=None)
        if res['status'] == 0: return {'status': 'OK'}
        return {'status': 'FAIL', 'detail': res['stderr']}

    def _encode_extensions(self, exts):
        "Internal: Encode an extension mapping into command-line options."
        if not exts: return ()
        ret = []
        for key, value in exts.items():
            if key == 'subjectAltName':
                for item in value:
                    if ',' in item:
                        raise ValidationError('SubjectAltName value has '
                            'unsupported comma')
                    elif ':' not in item:
                        raise ValidationError('SubjectAltName value missing '
                            'colon')
                if not value: continue
                ret.extend(('-addext', 'subjectAltName=' + ','.join(value)))
            else:
                raise ValidationError('Unrecognized extension {!r}'
                                      .format(key))
        return tuple(ret)

    def _create_cert(self, cmdline, cert_path, key_path, input=None):
        "Internal: Create a certificate and chmod its files."
        res = None
        try:
            res = self._run_openssl(cmdline, input)
            ret = {'status': 'OK'}
            if cert_path:
                if self.dry_run:
                    print(format_shell_line('chmod', '0444', cert_path))
                else:
                    os.chmod(cert_path, 0o444)
                ret['cert_path'] = cert_path
            if key_path:
                if self.dry_run:
                    print(format_shell_line('chmod', '0400', key_path))
                else:
                    os.chmod(key_path, 0o400)
                ret['key_path'] = key_path
        finally:
            if not res:
                if cert_path: self._silent_remove(cert_path)
                if key_path: self._silent_remove(key_path)
        return ret

    def prepare_storage(self, replace=False, readonly=True):
        """
        Create and initialize the certificate store (if necessary).

        If replace is true, any configuration files (of which there currently
        are none) are replaced regardless of whether they exist.

        If readonly is true, the operation will *not* fail if the user has
        insufficient permissions to modify the storage, but read-only access
        is still possible.
        """
        if self.dry_run:
            return
        os.makedirs(self.storage_dir, exist_ok=True)
        cert_dir = os.path.join(self.storage_dir, 'cert')
        os.makedirs(cert_dir, exist_ok=True)
        try:
            os.chmod(cert_dir, 0o755)
        except PermissionError:
            if not readonly: raise
        key_dir = os.path.join(self.storage_dir, 'key')
        os.makedirs(key_dir, exist_ok=True)
        try:
            os.chmod(key_dir, 0o700)
        except PermissionError:
            if not readonly: raise

    def list(self, basenames=None, verbose=False):
        """
        Return the names and metadata of the certificates with the given
        names.

        basenames is a list of certificates to prepare a listing of, or None
        to list all certificates.

        verbose indicates that listing entries should not only contain names
        but also metadata.
        """
        def format_timestamp(ts):
            "Format a timestamp into a human-readable string."
            return time.strftime('%Y-%m-%d %H:%M:%S Z', time.gmtime(ts))

        cert_dir = os.path.join(self.storage_dir, 'cert')
        if basenames is None:
            basenames = [n[:-4] for n in os.listdir(cert_dir)
                         if n.endswith('.pem')]
        result, warnings = [], []
        for basename in basenames:
            fullname = self._derive_paths(basename)[0]
            if not os.path.exists(fullname):
                raise InputError('Certificate {} does not exist'
                                 .format(basename))
            entry = [basename]
            result.append(entry)
            if not verbose: continue
            details = self._get_cert_meta(
                filename=os.path.join(cert_dir, fullname))
            if details['subject'][1] != basename:
                warnings.append('{}: Basename in certificate ({}) does not '
                                'match file name'
                                .format(basename, details['subject'][1]))
            entry.extend((
                ('type', '{}'.format(details['subject'][0])),
                ('issuer', '{} ({})'.format(details['issuer'][1],
                                            details['issuer'][0])),
                ('notBefore', format_timestamp(details['notBefore'])),
                ('notAfter', format_timestamp(details['notAfter']))
            ))
        return {'result': result, 'warnings': warnings}

    def _create_root(self, basename, ca, exts=None):
        "Internal: Root certificate creation implementation."
        cert_path, key_path = self._derive_paths(basename)
        if os.path.exists(cert_path):
            raise ValidationError('New certificate basename already in use')
        options = (
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
            '-days', str(self.new_cert_days),
            # Write certificate and key to files.
            '-out', cert_path, '-keyout', key_path
        )
        if not ca:
            # The secion name is mentioned in the openssl-cmp documentation.
            cert_options += ('-extensions', 'v3_ca')
        options += self._encode_extensions(exts)
        return self._create_cert(options, cert_path, key_path)

    def _create_derived(self, new_basename, parent_basename, ca, exts=None):
        "Internal: Non-root certificate creation implementation."
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
                    (UNIT_INTERMEDIATE if ca else UNIT_LEAF), new_basename),
                # Write the key to its final location but the request to
                # standard output.
                '-keyout', new_key_path
            ) + self._encode_extensions(exts))
            cert_options = (
                # Sign a certificate request.
                'x509', '-req',
                # Use the configured validity interval.
                '-days', str(self.new_cert_days),
                # Who needs *serial* numbers, anyway?
                '-set_serial', str(self.random.getrandbits(20 * 8 - 1)),
                # Use the given CA.
                '-CA', par_cert_path, '-CAkey', par_key_path,
                # Output the finished certificate to the correct location.
                '-out', new_cert_path
            )
            if ca:
                # The secion name is mentioned in the openssl-ca
                # documentation.
                cert_options += ('-extensions', 'v3_ca')
            ret = self._create_cert(cert_options, new_cert_path, new_key_path,
                                    res_request['stdout'])
            success = True
            return ret
        finally:
            if not success:
                self._silent_remove(new_cert_path)
                self._silent_remove(new_key_path)

    def create(self, new_basename, parent_basename=None, ca=False,
               exts=None):
        """
        Create a certificate.

        If parent_basename is not provided, the certificate will be a root; if
        ca is true, the certificate will be a CA certificate. exts is a
        mapping of extensions; presently, only subjectAltName is supported.
        """
        if parent_basename is None:
            return self._create_root(new_basename, ca, exts)
        else:
            return self._create_derived(new_basename, parent_basename, ca,
                                        exts)

    def remove(self, basename):
        """
        Delete the given certificate.
        """
        cert_path, key_path = self._derive_paths(basename)
        self._silent_remove(cert_path)
        self._silent_remove(key_path)

    def export(self, basename, cert_dest=None, chain_dest=None,
               root_dest=None, key_dest=None, new_owner=None, new_group=None):
        """
        Copy various data pertaining to the named certificate out of the
        store.

        cert_dest  is a filesystem path whither to write the certificate.
        chain_dest is a filesystem path whither to write the certificate's
                   chain (without the certificate itself and without the
                   root).
        root_dest  is a filesystem path whither to write the root of the
                   certificate's chain.
        key_dest   is a filesystem path whither to write the certificate's
                   private key.
        new_owner  is the name of a user (or a numeric user ID) to assign to
                   the exported files.
        new_group  is the name of a group (or a numeric group ID) to assign to
                   the exported files.
        If a *_dest parameter is omitted or None, the corresponding file is
        not written. If cert_dest is the same as root_dest and the certificate
        is self-signed (i.e. its own root), it is only written once. If
        new_owner or new_group is omitted or None, the corresponding part of
        the exported files' metadata is not changed.
        """
        cert_path, key_path = self._derive_paths(basename)
        chain = self._collect_chain(basename)
        ret = {'status': 'FAIL', 'warnings': []}
        verification_res = self._verify_chain([p[0] for p in chain])
        if verification_res['status'] != 'OK':
            ret['warnings'].append('Could not validate exported certificate '
                'chain:\n' + verification_res['detail'].rstrip('\n'))
        cert_written = chain_written = root_written = key_written = False
        try:
            if cert_dest is not None:
                self._write_and_adjust((chain[0][1],), cert_dest, 0o444,
                                       new_owner, new_group)
                cert_written = True
            if chain_dest is not None:
                self._write_and_adjust((p[1] for p in chain[1:-1]),
                                       chain_dest, 0o444,
                                       new_owner, new_group)
                chain_written = True
            if root_dest is not None:
                # Avoid writing the same certificate to, say, stdout twice.
                if len(chain) >= 2 or cert_dest is not root_dest:
                    self._write_and_adjust((chain[-1][1],), root_dest, 0o444,
                                           new_owner, new_group)
                    root_written = True
            if key_dest is not None:
                self._copy_and_adjust(key_path, key_dest, 0o400,
                                      new_owner, new_group)
                key_written = True
            ret['status'] = 'OK'
        finally:
            if ret['status'] != 'OK':
                if cert_written: self._silent_remove(cert_dest)
                if chain_written: self._silent_remove(chain_dest)
                if root_written: self._silent_remove(root_dest)
                if key_written: self._silent_remove(key_dest)
        return ret

def days_in(s):
    "Helper: Parse a --days command-line argument value."
    try:
        return int(s)
    except ValueError:
        today = datetime.date.today()
        then = parse_days_in(s, today)
        return (then - today).days

def chown_spec(s):
    "Helper: Parse a --chown command-line argument value."
    parts = s.split(':')
    if len(parts) == 1:
        return (parts[0] or None, parts[0] or None)
    elif len(parts) == 2:
        return (parts[0] or None, parts[1] or None)
    else:
        raise ValueError('Too many colons in new owner specification')

def derive_export_dest(filename, subext, condition=True):
    "Helper: Compute a certificate export result destination, or return None."
    if not condition: return None
    if not isinstance(filename, str): return filename
    root, ext = os.path.splitext(filename)
    return ''.join(root, ('.' if subext else ''), subext, ext)

def main():
    "Main function."
    def add_cert_params(p):
        "Helper: Configure the parameters common to new-root and new."
        p.add_argument('--key-spec',
            help='A string describing how to generate a private key (e.g. ' +
                 DEFAULT_NEW_KEY_SPEC + ').')
        p.add_argument('--hash',
            help='The cryptographic hash function to use for signatures.')
        p.add_argument('--days', type=days_in,
            help='How many days the new certificate should be valid for.')
        p.add_argument('--san', action='append', default=[],
            help='Subject Alternate Name for the certificate.')

    def get_exts(arguments):
        "Helper: Extract a certificate extension mapping from arguments."
        return {'subjectAltName': arguments.san}

    def layout_listing(data):
        "Helper: Prepare a certificate listing for columnar output."
        rows, rank = [], 0
        for data_row in data:
            last = len(data_row) - 1
            if last >= rank: rank = last + 1
            rows.append([])
            for i, item in enumerate(data_row):
                if i == 0 and i == last:
                    rows[-1].append(item)
                elif i == 0:
                    rows[-1].append(item + ':')
                elif i == last:
                    rows[-1].append('{}: {}'.format(*item))
                else:
                    rows[-1].append('{}: {};'.format(*item))
        widths = [0] * rank
        for row in rows:
            for i, item in enumerate(row):
                if len(item) > widths[i]:
                    widths[i] = len(item)
        result = []
        for row in rows:
            last = len(row) - 1
            result.append([])
            for i, item in enumerate(row):
                if i == last:
                    result[-1].extend((item, 0))
                else:
                    result[-1].extend((item, widths[i]))
            while len(result[-1]) < rank * 2:
                result[-1].extend(('', 0))
        fmt = ' '.join(['{:<{}}'] * len(widths))
        return fmt, result

    def print_warnings(warnings):
        "Helper: Print out a list of warnings (if any)."
        for warning in warnings:
            sys.stderr.write('WARNING: {}\n'.format(warning))

    def do_export(basename):
        "Helper: Actually perform the export of the named certificate."
        dest = arguments.output
        if dest is None: dest = basename + '.pem'
        if dest == '-': dest = sys.stdout
        cert_dest = derive_export_dest(dest, '', arguments.certificate)
        chain_dest = derive_export_dest(dest, 'chain', arguments.chain)
        root_dest = derive_export_dest(dest, 'root', arguments.root)
        key_dest = derive_export_dest(dest, 'key', arguments.key)
        res = ca.export(basename, cert_dest, chain_dest, root_dest,
                        key_dest, arguments.chown[0], arguments.chown[1])
        print_warnings(res['warnings'])

    # Prepare command line parser.
    p = argparse.ArgumentParser(
        description='Simple local X.509 certificate management.')
    p.add_argument('--store', '-S', metavar='<DIR>',
        help='The location of the certificate store.')
    p.add_argument('--user', '-U', action='store_const', dest='store',
        const=Ellipsis,
        help='Use ' + USER_STORAGE_DIR + ' as the certificate store.')
    p.add_argument('--openssl', metavar='<PATH>',
        help='The location of the openssl executable.')
    sp = p.add_subparsers(dest='action',
        description='The action to perform.')
    sp.required = True
    # (Subcommand init.)
    p_init = sp.add_parser('init',
        help='Initialize the certificate store (and do nothing else).')
    p_init.add_argument('--force', '-f', action='store_true',
        help='Replace configuration files that may have been modified to '
             'pristine copies.')
    # (Subcommand list.)
    p_list = sp.add_parser('list',
        help='Display certificates.')
    p_list.add_argument('-l', '--long', action='store_true',
        help='Display additional information about each certificate (beyond '
             'its name).')
    p_list.add_argument('name', nargs='*',
        help='The name of a certificate to display (defaults to all).')
    # (Subcommand new.)
    p_new = sp.add_parser('new',
        help='Create a new intermediate or leaf certificate.')
    add_cert_params(p_new)
    p_new.add_argument('--ca', '-a', action='store_const', const=True,
        help='Create an intermediate (CA) certificate (default if no '
             '--parent is supplied).')
    p_new.add_argument('--no-ca', '-l', action='store_const', dest='ca',
        const=False,
        help='Create a leaf (non-CA) certificate (default if a --parent is '
             'supplied).')
    p_new.add_argument('--parent', '-p', metavar='<NAME>',
        help='The name of the certificate to act as the issuer of the new '
             'one.')
    p_new.add_argument('name',
        help='The name of the new certificate.')
    # (Subcommand remove.)
    p_remove = sp.add_parser('remove',
        help='Delete one or more certificates.')
    p_remove.add_argument('name', nargs='+',
        help='The name of a certificate to delete.')
    # (Subcommand export.)
    p_export = sp.add_parser('export',
        help='Copy files associated with one or more certificates from the '
             'certificate store.')
    p_export.add_argument('--root', '-r', action='store_true',
        help='Export the root of the certificate\'s chain (sub-extension '
             '".root").')
    p_export.add_argument('--chain', '-c', action='store_true',
        help='Export a chain of intermediate certificates up to (but not '
             'including) the root (sub-extension ".chain").')
    p_export.add_argument('--certificate', '-s', action='store_true',
        help='Export the certificate itself (no sub-extension).')
    p_export.add_argument('--key', '-k', action='store_true',
        help='Export the certificate\'s private key (sub-extension ".key").')
    p_export.add_argument('--output', '-o', metavar='<FILENAME>',
        help='Where to write the certificate. The names of associated files '
             'are derived by inserting certain "sub-extensions" before this '
             'filename\'s extension (e.g., the private key of "cert.pem" is '
             'stored in "cert.key.pem"). Must not be used when exporting '
             'multiple certificates at once. If "-", the files are '
             'concatenated to standard output instead. Defaults to the name '
             'of the certificate followed by ".pem".')
    p_export.add_argument('--chown', '-U', metavar='<USER>[:<GROUP>]',
        type=chown_spec, default=(None, None),
        help='Change the owner and/or group of the exported files. If '
             '<GROUP> is omitted, it is taken to be the same as <OWNER>. '
             'Either may be the empty string to perform no change.')
    p_export.add_argument('name', nargs='+',
        help='The name of a certificate to export.')
    # Parse command line.
    arguments = p.parse_args()
    # Create driver object.
    kwargs = {
        'openssl_path': arguments.openssl,
        'storage_dir': arguments.store
    }
    if arguments.store is Ellipsis:
        kwargs['storage_dir'] = os.path.expanduser(USER_STORAGE_DIR)
    if hasattr(arguments, 'key_spec'):
        kwargs.update(
            new_key_spec=arguments.key_spec,
            new_cert_hash=arguments.hash,
            new_cert_days=arguments.days
        )
    ca = MiniCA(**kwargs)
    # Execute action.
    try:
        prepare_force = getattr(arguments, 'force', False)
        prepare_ro = (arguments.action not in ('init', 'new', 'remove'))
        ca.prepare_storage(prepare_force, prepare_ro)
        if arguments.action == 'init':
            pass
        elif arguments.action == 'list':
            res = ca.list(arguments.name or None, verbose=arguments.long)
            fmt, rows = layout_listing(res['result'])
            for row in rows:
                print(fmt.format(*row).rstrip())
            print_warnings(res['warnings'])
        elif arguments.action == 'new':
            if arguments.ca is None:
                ca_cert = (arguments.parent is None)
            else:
                ca_cert = arguments.ca
            ca.create(arguments.name, arguments.parent, ca_cert,
                      exts=get_exts(arguments))
        elif arguments.action == 'remove':
            for basename in arguments.name:
                ca.remove(basename)
        elif arguments.action == 'export':
            if len(arguments.name) > 1 and arguments.output is not None:
                raise SystemExit('ERROR: May not export multiple '
                    'certificates with --output.')
            for basename in arguments.name:
                do_export(basename)
        else:
            raise AssertionError('This should not happen?!')
    except Error as err:
        sys.stderr.write('ERROR: {}\n'.format(err))
        sys.stderr.flush()
        raise SystemExit(2)

if __name__ == '__main__': main()
