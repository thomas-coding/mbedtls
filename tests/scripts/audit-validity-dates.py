#!/usr/bin/env python3
#
# copyright the mbed tls contributors
# spdx-license-identifier: apache-2.0
#
# licensed under the apache license, version 2.0 (the "license"); you may
# not use this file except in compliance with the license.
# you may obtain a copy of the license at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Audit validity date of X509 crt/crl/csr.

This script is used to audit the validity date of crt/crl/csr used for testing.
It prints the information of X509 data whose validity duration does not cover
the provided validity duration. The data are collected from tests/data_files/
and tests/suites/*.data files by default.
"""

import os
import sys
import re
import typing
import argparse
import datetime
import glob
from enum import Enum

# The script requires cryptography >= 35.0.0 which is only available
# for Python >= 3.6. Disable the pylint error here until we were
# using modern system on our CI.
from cryptography import x509 #pylint: disable=import-error

# reuse the function to parse *.data file in tests/suites/
from generate_test_code import parse_test_data as parse_suite_data

class DataType(Enum):
    CRT = 1 # Certificate
    CRL = 2 # Certificate Revocation List
    CSR = 3 # Certificate Signing Request

class DataFormat(Enum):
    PEM = 1 # Privacy-Enhanced Mail
    DER = 2 # Distinguished Encoding Rules

class AuditData:
    """Store file, type and expiration date for audit."""
    #pylint: disable=too-few-public-methods
    def __init__(self, data_type: DataType, x509_obj):
        self.data_type = data_type
        self.filename = ""
        self.fill_validity_duration(x509_obj)

    def fill_validity_duration(self, x509_obj):
        """Fill expiration_date field from a x509 object"""
        # Certificate expires after "not_valid_after"
        # Certificate is invalid before "not_valid_before"
        if self.data_type == DataType.CRT:
            self.not_valid_after = x509_obj.not_valid_after
            self.not_valid_before = x509_obj.not_valid_before
        # CertificateRevocationList expires after "next_update"
        # CertificateRevocationList is invalid before "last_update"
        elif self.data_type == DataType.CRL:
            self.not_valid_after = x509_obj.next_update
            self.not_valid_before = x509_obj.last_update
        # CertificateSigningRequest is always valid.
        elif self.data_type == DataType.CSR:
            self.not_valid_after = datetime.datetime.max
            self.not_valid_before = datetime.datetime.min
        else:
            raise ValueError("Unsupported file_type: {}".format(self.data_type))

class X509Parser():
    """A parser class to parse crt/crl/csr file or data in PEM/DER format."""
    PEM_REGEX = br'-{5}BEGIN (?P<type>.*?)-{5}\n(?P<data>.*?)-{5}END (?P=type)-{5}\n'
    PEM_TAG_REGEX = br'-{5}BEGIN (?P<type>.*?)-{5}\n'
    PEM_TAGS = {
        DataType.CRT: 'CERTIFICATE',
        DataType.CRL: 'X509 CRL',
        DataType.CSR: 'CERTIFICATE REQUEST'
    }

    def __init__(self, backends: dict):
        self.backends = backends
        self.__generate_parsers()

    def __generate_parser(self, data_type: DataType):
        """Parser generator for a specific DataType"""
        tag = self.PEM_TAGS[data_type]
        pem_loader = self.backends[data_type][DataFormat.PEM]
        der_loader = self.backends[data_type][DataFormat.DER]
        def wrapper(data: bytes):
            pem_type = X509Parser.pem_data_type(data)
            # It is in PEM format with target tag
            if pem_type == tag:
                return pem_loader(data)
            # It is in PEM format without target tag
            if pem_type:
                return None
            # It might be in DER format
            try:
                result = der_loader(data)
            except ValueError:
                result = None
            return result
        wrapper.__name__ = "{}.parser[{}]".format(type(self).__name__, tag)
        return wrapper

    def __generate_parsers(self):
        """Generate parsers for all support DataType"""
        self.parsers = {}
        for data_type, _ in self.PEM_TAGS.items():
            self.parsers[data_type] = self.__generate_parser(data_type)

    def __getitem__(self, item):
        return self.parsers[item]

    @staticmethod
    def pem_data_type(data: bytes) -> str:
        """Get the tag from the data in PEM format

        :param data: data to be checked in binary mode.
        :return: PEM tag or "" when no tag detected.
        """
        m = re.search(X509Parser.PEM_TAG_REGEX, data)
        if m is not None:
            return m.group('type').decode('UTF-8')
        else:
            return ""

    @staticmethod
    def check_hex_string(hex_str: str) -> bool:
        """Check if the hex string is possibly DER data."""
        hex_len = len(hex_str)
        # At least 6 hex char for 3 bytes: Type + Length + Content
        if hex_len < 6:
            return False
        # Check if Type (1 byte) is SEQUENCE.
        if hex_str[0:2] != '30':
            return False
        # Check LENGTH (1 byte) value
        content_len = int(hex_str[2:4], base=16)
        consumed = 4
        if content_len in (128, 255):
            # Indefinite or Reserved
            return False
        elif content_len > 127:
            # Definite, Long
            length_len = (content_len - 128) * 2
            content_len = int(hex_str[consumed:consumed+length_len], base=16)
            consumed += length_len
        # Check LENGTH
        if hex_len != content_len * 2 + consumed:
            return False
        return True

class Auditor:
    """A base class for audit."""
    def __init__(self, verbose):
        self.verbose = verbose
        self.default_files = []
        self.audit_data = []
        self.parser = X509Parser({
            DataType.CRT: {
                DataFormat.PEM: x509.load_pem_x509_certificate,
                DataFormat.DER: x509.load_der_x509_certificate
            },
            DataType.CRL: {
                DataFormat.PEM: x509.load_pem_x509_crl,
                DataFormat.DER: x509.load_der_x509_crl
            },
            DataType.CSR: {
                DataFormat.PEM: x509.load_pem_x509_csr,
                DataFormat.DER: x509.load_der_x509_csr
            },
        })

    def error(self, *args):
        #pylint: disable=no-self-use
        print("Error: ", *args, file=sys.stderr)

    def warn(self, *args):
        if self.verbose:
            print("Warn: ", *args, file=sys.stderr)

    def parse_file(self, filename: str) -> typing.List[AuditData]:
        """
        Parse a list of AuditData from file.

        :param filename: name of the file to parse.
        :return list of AuditData parsed from the file.
        """
        with open(filename, 'rb') as f:
            data = f.read()
        result_list = []
        result = self.parse_bytes(data)
        if result is not None:
            result.filename = filename
            result_list.append(result)
        return result_list

    def parse_bytes(self, data: bytes):
        """Parse AuditData from bytes."""
        for data_type in list(DataType):
            try:
                result = self.parser[data_type](data)
            except ValueError as val_error:
                result = None
                self.warn(val_error)
            if result is not None:
                audit_data = AuditData(data_type, result)
                return audit_data
        return None

    def walk_all(self, file_list):
        """
        Iterate over all the files in the list and get audit data.
        """
        if not file_list:
            file_list = self.default_files
        for filename in file_list:
            data_list = self.parse_file(filename)
            self.audit_data.extend(data_list)

    @staticmethod
    def find_test_dir():
        """Get the relative path for the MbedTLS test directory."""
        if os.path.isdir('tests'):
            tests_dir = 'tests'
        elif os.path.isdir('suites'):
            tests_dir = '.'
        elif os.path.isdir('../suites'):
            tests_dir = '..'
        else:
            raise Exception("Mbed TLS source tree not found")
        return tests_dir

class TestDataAuditor(Auditor):
    """Class for auditing files in tests/data_files/"""
    def __init__(self, verbose):
        super().__init__(verbose)
        self.default_files = self.collect_default_files()

    def collect_default_files(self):
        """Collect all files in tests/data_files/"""
        test_dir = self.find_test_dir()
        test_data_folder = os.path.join(test_dir, 'data_files')
        data_files = []
        for (dir_path, _, file_names) in os.walk(test_data_folder):
            data_files.extend(os.path.join(dir_path, file_name)
                              for file_name in file_names)
        return data_files

class FileWrapper():
    """
    This a stub class of generate_test_code.FileWrapper.

    This class reads the whole file to memory before iterating
    over the lines.
    """

    def __init__(self, file_name):
        """
        Read the file and initialize the line number to 0.

        :param file_name: File path to open.
        """
        with open(file_name, 'rb') as f:
            self.buf = f.read()
        self.buf_len = len(self.buf)
        self._line_no = 0
        self._line_start = 0

    def __iter__(self):
        """Make the class iterable."""
        return self

    def __next__(self):
        """
        This method for returning a line of the file per iteration.

        :return: Line read from file.
        """
        # If we reach the end of the file.
        if not self._line_start < self.buf_len:
            raise StopIteration

        line_end = self.buf.find(b'\n', self._line_start) + 1
        if line_end > 0:
            # Find the first LF as the end of the new line.
            line = self.buf[self._line_start:line_end]
            self._line_start = line_end
            self._line_no += 1
        else:
            # No LF found. We are at the last line without LF.
            line = self.buf[self._line_start:]
            self._line_start = self.buf_len
            self._line_no += 1

        # Convert byte array to string with correct encoding and
        # strip any whitespaces added in the decoding process.
        return line.decode(sys.getdefaultencoding()).rstrip() + '\n'

    def get_line_no(self):
        """
        Gives current line number.
        """
        return self._line_no

    line_no = property(get_line_no)

class SuiteDataAuditor(Auditor):
    """Class for auditing files in tests/suites/*.data"""
    def __init__(self, options):
        super().__init__(options)
        self.default_files = self.collect_default_files()

    def collect_default_files(self):
        """Collect all files in tests/suites/*.data"""
        test_dir = self.find_test_dir()
        suites_data_folder = os.path.join(test_dir, 'suites')
        data_files = glob.glob(os.path.join(suites_data_folder, '*.data'))
        return data_files

    def parse_file(self, filename: str):
        """
        Parse a list of AuditData from file.

        :param filename: name of the file to parse.
        :return list of AuditData parsed from the file.
        """
        audit_data_list = []
        data_f = FileWrapper(filename)
        for _, _, _, test_args in parse_suite_data(data_f):
            for idx, test_arg in enumerate(test_args):
                match = re.match(r'"(?P<data>[0-9a-fA-F]+)"', test_arg)
                if not match:
                    continue
                if not X509Parser.check_hex_string(match.group('data')):
                    continue
                audit_data = self.parse_bytes(bytes.fromhex(match.group('data')))
                if audit_data is None:
                    continue
                audit_data.filename = "{}:{}:{}".format(filename,
                                                        data_f.line_no,
                                                        idx + 1)
                audit_data_list.append(audit_data)

        return audit_data_list

def list_all(audit_data: AuditData):
    print("{}\t{}\t{}\t{}".format(
        audit_data.not_valid_before.isoformat(timespec='seconds'),
        audit_data.not_valid_after.isoformat(timespec='seconds'),
        audit_data.data_type.name,
        audit_data.filename))

def main():
    """
    Perform argument parsing.
    """
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('-a', '--all',
                        action='store_true',
                        help='list the information of all the files')
    parser.add_argument('-v', '--verbose',
                        action='store_true', dest='verbose',
                        help='show warnings')
    parser.add_argument('--not-before', dest='not_before',
                        help=('not valid before this date (UTC, YYYY-MM-DD). '
                              'Default: today'),
                        metavar='DATE')
    parser.add_argument('--not-after', dest='not_after',
                        help=('not valid after this date (UTC, YYYY-MM-DD). '
                              'Default: not-before'),
                        metavar='DATE')
    parser.add_argument('files', nargs='*', help='files to audit',
                        metavar='FILE')

    args = parser.parse_args()

    # start main routine
    td_auditor = TestDataAuditor(args.verbose)
    sd_auditor = SuiteDataAuditor(args.verbose)

    if args.files:
        data_files = args.files
        suite_data_files = args.files
    else:
        data_files = td_auditor.default_files
        suite_data_files = sd_auditor.default_files

    if args.not_before:
        not_before_date = datetime.datetime.fromisoformat(args.not_before)
    else:
        not_before_date = datetime.datetime.today()
    if args.not_after:
        not_after_date = datetime.datetime.fromisoformat(args.not_after)
    else:
        not_after_date = not_before_date

    td_auditor.walk_all(data_files)
    sd_auditor.walk_all(suite_data_files)
    audit_results = td_auditor.audit_data + sd_auditor.audit_data

    # we filter out the files whose validity duration covers the provided
    # duration.
    filter_func = lambda d: (not_before_date < d.not_valid_before) or \
                            (d.not_valid_after < not_after_date)

    if args.all:
        filter_func = None

    for d in filter(filter_func, audit_results):
        list_all(d)

    print("\nDone!\n")

if __name__ == "__main__":
    main()
