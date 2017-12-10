#!/usr/bin/env python
import struct
import logging
import sys
from datetime import datetime
from collections import OrderedDict


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
        self.optional_header_offs = None  # needs to be computed dynamically
        self.image_base_addr = None # needs to be computed dynamically

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        image_base = self.get_image_base()
        logging.info('PE Image Base: 0x{:x}'.format(image_base))
        data_directory_array_offs = self.get_data_directory_array_offs()
        logging.info('PE OptionalHeader.DataDirectory array RVA: 0x{:x}'.format(data_directory_array_offs))
        import_directory_offs = self.get_import_directory_offs()
        logging.info('PE OptionalHeader.DataDirectory[1] (Import Directory) RVA: 0x{:x}'.format(import_directory_offs))
        import_descriptor_offs = self.get_first_import_descriptor_offs()
        logging.info('PE Import Descriptor RVA: 0x{:x}'.format(import_descriptor_offs))
        logging.info('PE Import Descriptor VA: 0x{:x}'.format(image_base + import_descriptor_offs))
        import_descriptor_size = self.get_import_descriptor_size()
        logging.info('PE Import Descriptor size: 0x{:x} = {}'.format(import_descriptor_size, import_descriptor_size))

    def get_pe_header_offs(self):
        if self.pe_header_offs:
            return self.pe_header_offs
        e_lfanew_offs = 0x3C
        # format string: <: little endian. L: 4 bytes (1 dword)
        pe_header_offs = struct.unpack_from('<L', self.bin_contents, self.image_dos_header_offs + e_lfanew_offs)
        self.pe_header_offs = pe_header_offs[0]
        return self.pe_header_offs

    def get_optional_header_offs(self):
        if self.optional_header_offs:
            return self.optional_header_offs
        self.optional_header_offs = self.get_pe_header_offs() + 0x18
        return self.optional_header_offs

    def get_image_base(self):
        if self.image_base_addr:
            return self.image_base_addr
        self.optional_header_offs = self.get_optional_header_offs()
        image_base_offs = 0x1C
        # format string: <: little endian. L: 4 bytes (1 dword)
        image_base_value = struct.unpack_from('<L', self.bin_contents, self.optional_header_offs + image_base_offs)
        self.image_base_addr = image_base_value[0]
        return self.image_base_addr

    def get_data_directory_array_offs(self):  # _IMAGE_DATA_DIRECTORY DataDirectory[16]; from OptionalHeader
        optional_header_offs = self.get_optional_header_offs()
        data_directories_offs = optional_header_offs + 0x60
        return data_directories_offs

    def get_import_directory_offs(self):  # IMAGE_DIRECTORY_ENTRY_IMPORT (DataDirectory[1])
        data_directory_array_offs = self.get_data_directory_array_offs()
        image_data_directory_size = 0x8  # two dwords
        return data_directory_array_offs + image_data_directory_size * 1

    def get_first_import_descriptor_offs(self):
        import_directory_offs = self.get_import_directory_offs()
        virtual_address_offs = 0x0
        # format string: <: little endian. H: 2 bytes (1 word)
        import_descriptor_offs = struct.unpack_from('<H', self.bin_contents, import_directory_offs + virtual_address_offs)
        return import_descriptor_offs[0]

    def get_import_descriptor_size(self):
        import_directory_offs = self.get_import_directory_offs()
        size_offs = 0x4
        # format string: <: little endian. H: 2 bytes (1 word)
        import_descriptor_size = struct.unpack_from('<H', self.bin_contents, import_directory_offs + size_offs)
        return import_descriptor_size[0]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
