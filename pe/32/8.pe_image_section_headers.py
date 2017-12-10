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

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        number_of_sections = self.get_fileheader_num_of_sections()
        logging.info('PE Number of Sections: {}'.format(number_of_sections))
        section_headers_info = self.get_sections_info()
        self._log_section_headers_info(section_headers_info)

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

    def get_fileheader_num_of_sections(self):
        self.file_header_offs = self.get_file_header_offs()
        num_of_sections_offs = 0x2
        # format string: <: little endian. H: 2 bytes (1 word)
        num_of_sections_value = struct.unpack_from('<H', self.bin_contents, self.file_header_offs + num_of_sections_offs)
        return num_of_sections_value[0]

    def get_optional_header_offs(self):
        if self.optional_header_offs:
            return self.optional_header_offs
        return self.get_pe_header_offs() + 0x18

    def get_sections_info(self):
        sections_info = []
        optional_header_size = self.get_file_header_optional_header_size()
        num_of_sections = self.get_fileheader_num_of_sections()
        section_headers_offs = self.get_optional_header_offs() + optional_header_size
        for section_header_num in range(num_of_sections):
            sections_info.append(self.get_section_info(section_headers_offs, section_header_num))
        return sections_info

    def get_file_header_optional_header_size(self):
        self.file_header_offs = self.get_file_header_offs()
        optional_header_size_offs = 0x10
        # format string: <: little endian. H: 2 bytes (1 word)
        size_of_optional_header = struct.unpack_from('<H', self.bin_contents, self.file_header_offs + optional_header_size_offs)
        return size_of_optional_header[0]

    def get_section_info(self, section_headers_offs, section_header_num):
        section_header_info = OrderedDict({})
        header_size = 0x24 + 4  # +4 comes from sizeof(IMAGE_SECTION_HEADER.Characteristics) = sizeof(1 dword) = 4 bytes
        section_header_offs = section_headers_offs + header_size * section_header_num
        section_header_info['Name'] = self.get_section_name(section_header_offs)
        section_header_info['Virtual Size'] = self.get_section_virtual_size(section_header_offs)
        section_header_info['Virtual Address'] = self.get_section_virtual_address(section_header_offs)
        section_header_info['Size of Raw Data'] = self.get_section_size_of_raw_data(section_header_offs)
        section_header_info['Pointer to Raw Data'] = self.get_section_pointer_to_raw_data(section_header_offs)
        section_header_info['Characteristics'] = self.get_section_characteristics(section_header_offs)
        return section_header_info

    def get_section_name(self, section_header_offs):
        # format string: >: big endian. Q: 8 bytes (2 dwords)
        section_name = struct.unpack_from('>Q', self.bin_contents, section_header_offs)
        section_name = self._bytes_to_string(section_name[0], 8)
        return section_name

    def get_section_virtual_size(self, section_header_offs):
        virtual_size_offs = section_header_offs + 0x8
        # format string: <: little endian. L: 4 bytes (1 dword)
        virtual_size = struct.unpack_from('<L', self.bin_contents, virtual_size_offs)
        return virtual_size[0]

    def get_section_virtual_address(self, section_header_offs):
        virtual_address_offs = section_header_offs + 0xc
        # format string: <: little endian. L: 4 bytes (1 dword)
        virtual_size = struct.unpack_from('<L', self.bin_contents, virtual_address_offs)
        return virtual_size[0]

    def get_section_size_of_raw_data(self, section_header_offs):
        size_of_raw_data_offs = section_header_offs + 0x10
        # format string: <: little endian. L: 4 bytes (1 dword)
        virtual_size = struct.unpack_from('<L', self.bin_contents, size_of_raw_data_offs)
        return virtual_size[0]

    def get_section_pointer_to_raw_data(self, section_header_offs):
        pointer_to_raw_data_offs = section_header_offs + 0x14
        # format string: <: little endian. L: 4 bytes (1 dword)
        virtual_size = struct.unpack_from('<L', self.bin_contents, pointer_to_raw_data_offs)
        return virtual_size[0]

    def get_section_characteristics(self, section_header_offs):
        characteristics_offs = section_header_offs + 0x24
        # format string: <: little endian. L: 4 bytes (1 dword)
        characteristics = struct.unpack_from('<L', self.bin_contents, characteristics_offs)
        return characteristics[0]

    @staticmethod
    def _bytes_to_string(value, length):
        # https://gph.is/1KjihQe (https://stackoverflow.com/questions/3673428/convert-int-to-ascii-and-back-in-python)
        return ''.join(chr((value >> 8 * (length - byte - 1)) & 0xFF) for byte in range(length))

    @staticmethod
    def _log_section_headers_info(section_headers_info):
        for section_header_info in section_headers_info:
            for key in section_header_info:
                if key == 'Name':
                    logging.info('{}: {}'.format(key, section_header_info[key]))
                elif key == 'Characteristics':
                    section_perms = 'r' if section_header_info[key] & 0x40000000 else '.'
                    section_perms = section_perms + 'w' if section_header_info[key] & 0x80000000 else section_perms + '-'
                    section_perms = section_perms + 'x' if section_header_info[key] & 0x20000000 else section_perms + '-'
                    logging.info('--> Permissions: {}'.format(section_perms))
                else:
                    logging.info('--> {}: 0x{:x}'.format(key, section_header_info[key]))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
