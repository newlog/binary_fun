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
        pe_arch = self.get_fileheader_machine()
        logging.info('PE architecture "{}"'.format(pe_arch))
        characteristics = self.get_fileheader_characteristics()
        logging.info('PE Characteristics: {}'.format(characteristics))

    def get_mz_header_contents(self):
        e_magic_offs = 0
        # format string: >: big endian. h: 2 bytes (1 word)
        mz_header_bytes = struct.unpack_from('>H', self.bin_contents, self.image_dos_header_offs + e_magic_offs)
        mz_header_string = self._long_to_string(mz_header_bytes[0], 2)
        return mz_header_string

    def get_pe_header_offs(self):
        if self.pe_header_offs:
            return self.pe_header_offs
        e_lfanew_offs = 0x3C
        # format string: <: little endian. L: 4 bytes (1 dword)
        pe_header_offs = struct.unpack_from('<L', self.bin_contents, self.image_dos_header_offs + e_lfanew_offs)
        return pe_header_offs[0]

    def get_file_header_offs(self):
        if self.file_header_offs:
            return self.file_header_offs
        return self.get_pe_header_offs() + 0x4

    def get_fileheader_timedatestamp(self):
        timedatestamp_offs = 0x4
        # format string: <: little endian. L: 4 bytes (1 dword)
        timedatestamp_value = struct.unpack_from('<L', self.bin_contents, self.get_file_header_offs() + timedatestamp_offs)
        readable_date = self._from_timestamp_to_readable_date(timedatestamp_value[0])
        return readable_date

    def get_fileheader_machine(self):
        self.file_header_offs = self.get_file_header_offs()
        machine_offs = 0x0
        # format string: <: little endian. h: 2 bytes (1 word)
        machine_value = struct.unpack_from('<H', self.bin_contents, self.file_header_offs + machine_offs)
        readable_arch = self._translate_arch(machine_value[0])
        return readable_arch

    def get_fileheader_characteristics(self):
        self.file_header_offs = self.get_file_header_offs()
        characteristics_offs = 0x12
        # format string: <: little endian. h: 2 bytes (1 word)
        characteristics_value = struct.unpack_from('<H', self.bin_contents, self.file_header_offs + characteristics_offs)
        readable_characteristics = self._translate_characteristics(characteristics_value[0])
        return readable_characteristics

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

    @staticmethod
    def _translate_arch(value):
        if value == 0x14C:
            readable_arch = 'x86'
        elif value == 0x8664:
            readable_arch = 'x86_64'
        elif value == 0x200:
            readable_arch = 'IA64'
        else:
            readable_arch = 'Unsupported Architecture'
        return readable_arch

    @staticmethod
    def _translate_characteristics(value):
        is_dll = 'DLL: True' if value & 0x2000 == 0x2000 else 'DLL: False'
        is_32bit = '32-bit: True' if value & 0x0100 == 0x0100 else '32-bit: False'
        is_16bit = '16-bit: True' if value & 0x0040 == 0x0040 else '16-bit: False'
        is_stripped = 'Stripped: True' if value & 0x0200 == 0x0200 else 'Stripped: False'
        readable_characteristics = ', '.join([is_dll, is_32bit, is_16bit, is_stripped])
        return readable_characteristics


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
