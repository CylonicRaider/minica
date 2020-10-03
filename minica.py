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
import shutil
import argparse
import email.utils

VALID_NAME = re.compile(r'^[a-zA-Z0-9._-]+$')

ORGANIZATION = 'Local'
UNIT_ROOT = 'Root'
UNIT_INTERMEDIATE = 'Intermediate'
UNIT_LEAF = 'Leaf'

OPENSSL_PATH = '/usr/bin/openssl'

STORAGE_DIR = '/etc/minica'
DEFAULT_NEW_KEY_SPEC = 'rsa:4096'
DEFAULT_NEW_CERT_HASH = 'sha256'
DEFAULT_NEW_CERT_DAYS = 30

PARSE_LINE = re.compile(r'^([a-zA-Z0-9]+)\s*=\s*(.*)$')
DAYS_IN_TOKEN = re.compile(r'([+-]?[1-9][0-9]*)([dwmyDWMY])')
DAYS_IN_PATTERN = re.compile(
    r'^(?:[+-]?[1-9][0-9]*[dwmyDWMY]\s*)*(?:[+-]?[1-9][0-9]*[dwmyDWMY])$')
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

class MiniCA:
    def __init__(self, openssl_path=None, storage_dir=None, new_key_spec=None,
                 new_cert_hash=None, new_cert_days=None):
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
                                stderr=subprocess.PIPE,
                                universal_newlines=True)
        stdout, stderr = proc.communicate(input)
        status = proc.wait()
        if require_status is not None and status != require_status:
            raise ExecutionError('openssl exited with unexpected status {}'
                                 .format(status), status, stderr)
        return {'status': status, 'stdout': stdout, 'stderr': stderr}

    def _write_and_adjust(self, source, destination, mode, owner, group):
        with open(destination, 'w') as df:
            os.chmod(df.fileno(), mode)
            if owner is not None or group is not None:
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
            raise ValidationError('Invalid {}certificate basename'
                                  .format(detail + ' ' if detail else ''))
        return (os.path.join(self.storage_dir, 'cert', basename + '.pem'),
                os.path.join(self.storage_dir, 'key', basename + '.pem'))

    def _get_cert_meta(self, filename=None, input=None):
        def decode_rdn(name):
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
        os.makedirs(self.storage_dir, exist_ok=True)
        cert_dir = os.path.join(self.storage_dir, 'cert')
        os.makedirs(cert_dir, exist_ok=True)
        os.chmod(cert_dir, 0o755)
        key_dir = os.path.join(self.storage_dir, 'key')
        os.makedirs(key_dir, exist_ok=True)
        os.chmod(key_dir, 0o700)

    def list(self, basenames=None, verbose=False):
        def format_timestamp(ts):
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
            '-days', str(self.new_cert_days),
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
                    (UNIT_INTERMEDIATE if ca else UNIT_LEAF), new_basename),
                # Write the key to its final location but the request to
                # standard output.
                '-keyout', new_key_path
            ))
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
        ret = {'status': 'FAIL', 'warnings': ''}
        verification_res = self._verify_chain([p[0] for p in chain])
        if verification_res['status'] != 'OK':
            ret['warnings'] = verification_res['detail']
        cert_written = chain_written = root_written = key_written = False
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

def derive_export_path(filename, subext, condition=True):
    "Helper: Compute a certificate export result path, or return None."
    if not condition: return None
    root, ext = os.path.splitext(filename)
    return '{}.{}{}'.format(root, subext, ext)

def main():
    "Main function."
    def add_cert_params(p):
        p.add_argument('--key-spec',
            help='A string describing how to generate a private key (e.g. ' +
                 DEFAULT_NEW_KEY_SPEC + ').')
        p.add_argument('--hash',
            help='The cryptographic hash function to use for signatures.')
        p.add_argument('--days', type=days_in,
            help='How many days the new certificate should be valid for.')

    def layout_listing(data):
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

    # Prepare command line parser.
    p = argparse.ArgumentParser(
        description='Simple local X.509 certificate management.')
    p.add_argument('-S', '--store', metavar='<DIR>',
        help='The location of the certificate store.')
    p.add_argument('--openssl', metavar='<PATH>',
        help='The location of the openssl executable.')
    sp = p.add_subparsers(dest='action',
        description='The action to perform.')
    sp.required = True
    # (Subcommand init.)
    p_init = sp.add_parser('init',
        help='Initialize the certificate store (and do nothing else).')
    p_init.add_argument('--force', '-f', action='store_true',
        help='Replace configuration files that may have been modified by '
             'pristine copies.')
    # (Subcommand list.)
    p_list = sp.add_parser('list',
        help='Display certificates.')
    p_list.add_argument('-l', '--long', action='store_true',
        help='Display additional information about each certificate (beyond '
             'its name).')
    p_list.add_argument('name', nargs='*',
        help='The name of a certificate to display (defaults to all).')
    # (Subcommand new-root.)
    p_new_root = sp.add_parser('new-root',
        help='Create a new root certificate.')
    add_cert_params(p_new_root)
    p_new_root.add_argument('name',
        help='The name of the new certificate.')
    # (Subcommand new.)
    p_new = sp.add_parser('new',
        help='Create a new intermediate or leaf certificate.')
    add_cert_params(p_new)
    p_new.add_argument('--ca', '-a', action='store_true',
        help='Create an intermediate (CA) certificate instead of a leaf one.')
    p_new.add_argument('--parent', '-p', metavar='<NAME>', required=True,
        help='The name of the certificate to act as the issuer of the new '
             'one.')
    p_new.add_argument('name',
        help='The name of the new certificate.')
    # (Subcommand remove.)
    p_remove = sp.add_parser('remove',
        help='Delete a certificate.')
    p_remove.add_argument('name',
        help='The name of the certificate to delete.')
    # (Subcommand export.)
    p_export = sp.add_parser('export',
        help='Copy a certificate (and associated files) from the certificate '
             'store.')
    p_export.add_argument('--root', '-r', action='store_true',
        help='Export the root of the certificate\'s chain (sub-extension '
             '".root").')
    p_export.add_argument('--chain', '-c', action='store_true',
        help='Export a chain of intermediate certificates up to (but not '
             'including) the root (sub-extension ".chain").')
    p_export.add_argument('--key', '-k', action='store_true',
        help='Export the certificate\'s private key (sub-extension ".key").')
    p_export.add_argument('--output', '-o', metavar='<FILENAME>',
        help='Where to write the certificate. The names of associated files '
             'are derived by inserting certain "sub-extensions" before this '
             'filename\'s extension (e.g., the private key of "cert.pem" is '
             'stored in "cert.key.pem"). Defaults to the name of the '
             'certificate followed by ".pem".')
    p_export.add_argument('--chown', metavar='<USER>[:<GROUP>]',
        type=chown_spec, default=(None, None),
        help='Change the owner and/or group of the exported files. If '
             '<GROUP> is omitted, it is taken to be the same as <OWNER>. '
             'Either may be the empty string to perform no change.')
    p_export.add_argument('name',
        help='The name of the certificate to export.')
    # Parse command line.
    arguments = p.parse_args()
    # Create driver object.
    kwargs = {
        'openssl_path': arguments.openssl,
        'storage_dir': arguments.store
    }
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
        ca.prepare_storage(prepare_force)
        if arguments.action == 'init':
            pass
        elif arguments.action == 'list':
            res = ca.list(arguments.name or None, verbose=arguments.long)
            fmt, rows = layout_listing(res['result'])
            for row in rows:
                print(fmt.format(*row))
            for warning in res['warnings']:
                sys.stderr.write('WARNING: {}\n'.format(warning))
        elif arguments.action == 'new-root':
            ca.create_root(arguments.name)
        elif arguments.action == 'new':
            if arguments.ca:
                ca.create_intermediate(arguments.name, arguments.parent)
            else:
                ca.create_leaf(arguments.name, arguments.parent)
        elif arguments.action == 'remove':
            ca.remove(arguments.name)
        elif arguments.action == 'export':
            cert_dest = arguments.output
            if cert_dest is None: cert_dest = arguments.name + '.pem'
            chain_dest = derive_export_path(cert_dest, 'chain',
                                            arguments.chain)
            root_dest = derive_export_path(cert_dest, 'root', arguments.root)
            key_dest = derive_export_path(cert_dest, 'key', arguments.key)
            res = ca.export(arguments.name, cert_dest, chain_dest, root_dest,
                            key_dest, arguments.chown[0], arguments.chown[1])
            if res['warnings']:
                sys.stderr.write('WARNING: Could not validate exported '
                                 'certificate chain:\n' +
                                 res['warnings'])
        else:
            raise AssertionError('This should not happen?!')
    except Error as err:
        sys.stderr.write('ERROR: {}\n'.format(err))
        sys.stderr.flush()
        raise SystemExit(2)

if __name__ == '__main__': main()
