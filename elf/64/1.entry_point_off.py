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


class ParseELF64(object):

    def execute(self, bin_path):
        bin_contents = FileUtils.read_file(bin_path)
        if bin_contents:
            e_entry_value = self.get_entry_point_off(bin_contents)
            logging.info('e_entry: 0x{:x}'.format(e_entry_value))

    def get_entry_point_off(self, bin_contents):
        e_entry_offs = 0x18
        # format string: <: little endian. Q: 8 bytes
        e_entry_value = struct.unpack_from('<Q', bin_contents, e_entry_offs) 
        return e_entry_value[0]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParseELF64()
        success = parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))

