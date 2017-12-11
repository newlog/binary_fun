#!/usr/bin/env python
import struct
import logging
import sys
from libs.pe_sections_utils import PESectionUtils


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
        self.section_headers_info = None
        self.pe_section_utils = None

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        self.pe_section_utils = PESectionUtils(self.bin_contents)
        self.section_headers_info = self.pe_section_utils.get_sections_info()
        imported_dlls = self.get_imported_dlls()
        logging.info('PE Imported DLLs #: {}'.format(len(imported_dlls)))
        logging.info('PE Imported DLLs: \n- {}'.format('\n- '.join(imported_dlls)))

    def get_imported_dlls(self):
        dll_names = []
        current_import_descriptor = self.get_first_import_descriptor_foff()
        import_descriptor_size = 0x14  # self.get_import_descriptor_size()
        while True:
            name = self.get_dll_name(current_import_descriptor)
            if not name:
                break
            dll_names.append(name)
            current_import_descriptor += import_descriptor_size
        return dll_names

    def get_data_directory_array_offs(self):  # _IMAGE_DATA_DIRECTORY DataDirectory[16]; from OptionalHeader
        optional_header_offs = self.pe_section_utils.get_optional_header_offs()
        # offsets in Ero's poster are wrong starting with the second QWORD (SizeOfStackReserve). The +0x10 adjusts it.
        data_directories_offs = optional_header_offs + 0x60 + 0x10
        return data_directories_offs

    def get_import_directory_offs(self):  # IMAGE_DIRECTORY_ENTRY_IMPORT (DataDirectory[1])
        data_directory_array_offs = self.get_data_directory_array_offs()
        image_data_directory_size = 0x8  # two dwords
        return data_directory_array_offs + image_data_directory_size * 1

    def get_import_descriptor_size(self):
        import_directory_offs = self.get_import_directory_offs()
        size_offs = 0x4
        import_descriptor_size = self._unpack_word(self.bin_contents, import_directory_offs + size_offs)
        return import_descriptor_size

    def get_first_import_descriptor_rva(self):
        import_directory_offs = self.get_import_directory_offs()
        virtual_address_offs = 0x0
        import_descriptor_rva = self._unpack_word(self.bin_contents, import_directory_offs + virtual_address_offs)
        return import_descriptor_rva

    def get_first_import_descriptor_foff(self):
        import_directory_offs = self.get_first_import_descriptor_rva()
        return self._rva_to_file_offset(import_directory_offs)

    def get_dll_name(self, import_descriptor_addr):
        name_offs = 0xC
        name_rva = self._unpack_dword(self.bin_contents, import_descriptor_addr + name_offs)
        name_foff = self._rva_to_file_offset(name_rva)
        name = self._read_null_terminated_ascii_string(name_foff)
        return name

    def _read_null_terminated_ascii_string(self, starting_addr):
        idx = 0
        ascii_string = ''
        while ord(self.bin_contents[starting_addr + idx]) != 0 and starting_addr + idx < len(self.bin_contents):
            ascii_string += self.bin_contents[starting_addr + idx]
            idx += 1
        return ascii_string

    def _rva_to_file_offset(self, rva):
        file_offs = -1
        for section_info in self.section_headers_info:
            if self._rva_belongs_to_section(rva, section_info):
                file_offs = rva - section_info['Virtual Address'] + section_info['Pointer to Raw Data']
                break
        return file_offs

    @staticmethod
    def _rva_belongs_to_section(rva, section_info):
        return section_info['Virtual Address'] <= rva < section_info['Virtual Address'] + section_info['Virtual Size']

    @staticmethod
    def _unpack_dword(contents, offs):
        # format string: <: little endian. L: 4 bytes (1 dword)
        return struct.unpack_from('<L', contents, offs)[0]

    @staticmethod
    def _unpack_word(contents, offs):
        # format string: <: little endian. H: 2 bytes (1 word)
        return struct.unpack_from('<H', contents, offs)[0]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
