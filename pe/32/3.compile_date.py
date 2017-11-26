#!/usr/bin/env python
import struct
import logging
import sys
from datetime import datetime


class FileUtils(object):

    @staticmethod
    def read_file(path):
        file_contents = None
        try:
            with open(path, 'rb') as fd:
                file_contents = fd.read()
        except IOError as e:
            logging.error('Error reading file "{}". Error: {}'.format(path, e))
        return file_contents


class ParsePE32(object):

    def __init__(self):
        self.bin_contents = None
        self.image_dos_header_offs = 0
        self.pe_header_offs = None  # needs to be computed dynamically
        self.file_header_offs = None  # needs to be computed dynamically

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        mz_header_string = self.get_mz_header_contents()
        logging.info('mz_header: {}'.format(mz_header_string))
        self.pe_header_offs = self.get_pe_header_offs()
        logging.info('pe_header_offs: 0x{:X}'.format(self.pe_header_offs))
        compilation_time = self.get_fileheader_timedatestamp()
        logging.info('PE was compiled at "{}"'.format(compilation_time))

    def get_mz_header_contents(self):
        e_magic_offs = 0
        # format string: >: big endian. h: 2 bytes (1 word)
        mz_header_bytes = struct.unpack_from('>h', self.bin_contents, self.image_dos_header_offs + e_magic_offs)
        mz_header_string = self._long_to_string(mz_header_bytes[0], 2)
        return mz_header_string

    def get_pe_header_offs(self):
        e_lfanew_offs = 0x3C
        # format string: <: little endian. L: 4 bytes (1 dword)
        pe_header_offs = struct.unpack_from('<L', self.bin_contents, self.image_dos_header_offs + e_lfanew_offs)
        return pe_header_offs[0]

    def get_fileheader_timedatestamp(self):
        self.file_header_offs = self.pe_header_offs + 0x4
        timedatestamp_offs = 0x4
        # format string: <: little endian. L: 4 bytes (1 dword)
        timedatestamp_value = struct.unpack_from('<L', self.bin_contents, self.file_header_offs + timedatestamp_offs)
        readable_date = self._from_timestamp_to_readable_date(timedatestamp_value[0])
        return readable_date

    @staticmethod
    def _long_to_string(value, length):
        # https://gph.is/1KjihQe (https://stackoverflow.com/questions/3673428/convert-int-to-ascii-and-back-in-python)
        return ''.join(chr((value >> 8 * (length - byte - 1)) & 0xFF) for byte in range(length))

    @staticmethod
    def _from_timestamp_to_readable_date(timestamp):
        readable_date = ''
        try:
            utc_time = datetime.utcfromtimestamp(timestamp)
            readable_date = utc_time.strftime("%Y-%m-%d %H:%M:%S.%f+00:00 (UTC)")
        except ValueError as e:
            logging.error('Timestamp "{}" could not be converted to an UTC date. Error: {}'.format(timestamp, e))
        return readable_date


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
