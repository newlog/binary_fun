#!/usr/bin/env python
import struct
import logging
import sys


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

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        mz_header_string = self.get_mz_header_contents()
        logging.info('mz_header: {}'.format(mz_header_string))
        pe_header_offs = self.get_pe_header_offs()
        logging.info('pe_header_offs: 0x{:X}'.format(pe_header_offs))

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

    @staticmethod
    def _long_to_string(value, length):
        # https://gph.is/1KjihQe (https://stackoverflow.com/questions/3673428/convert-int-to-ascii-and-back-in-python)
        return ''.join(chr((value >> 8 * (length - byte - 1)) & 0xFF) for byte in range(length))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
