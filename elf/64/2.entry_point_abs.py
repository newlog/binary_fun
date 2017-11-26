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

    def __init__(self):
        self.bin_contents = None

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_elf64()

    def parse_elf64(self):
        e_entry_value = self.get_entry_point_off()
        p_vaddr_value = self.get_virtual_base_addr()
        logging.info('e_entry: 0x{:x}'.format(e_entry_value))
        logging.info('p_vaddr: 0x{:x}'.format(p_vaddr_value))
        logging.info('Absolute Entry Point Address: 0x{:x}'.format(e_entry_value + p_vaddr_value))

    def get_entry_point_off(self):
        elf_header_offs = 0
        e_entry_offs = 24
        # format string: <: little endian. Q: 8 bytes
        e_entry_value = struct.unpack_from('<Q', self.bin_contents, elf_header_offs + e_entry_offs) 
        return e_entry_value[0]

    def get_virtual_base_addr(self):
        program_header_table_offs = 0x40
        p_vaddr_relative_offs = 25
        p_vaddr_value = struct.unpack_from('<Q', self.bin_contents, program_header_table_offs + p_vaddr_relative_offs) 
        return p_vaddr_value[0]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParseELF64()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))

