#!/usr/bin/env python
import struct
import logging
import sys
from libs.pe_sections_utils import PESectionUtils
from libs.pe_data_directory_utils import PEDataDirectoryUtils


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
        self.data_directory_info = None
        self.pe_section_utils = None
        self.pe_data_directory_utils = None
        self.export_directory_foff = None

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        self.pe_section_utils = PESectionUtils(self.bin_contents)
        self.section_headers_info = self.pe_section_utils.get_sections_info()
        self.pe_data_directory_utils = PEDataDirectoryUtils(self.bin_contents)
        self.data_directory_info = self.pe_data_directory_utils.get_data_directories_info()
        self.export_directory_foff = self.get_export_descriptor_directory_foff()
        if self.has_exports():
            number_of_functions = self.get_number_of_functions()
            logging.info('Number of Functions: {}'.format(number_of_functions))
            number_of_names = self.get_number_of_names()
            logging.info('Number of Names: {}'.format(number_of_names))
            exported_functions_by_name = self.get_pe_dll_exported_functions()
            logging.info('PE Exported Functions By Name: {}'.format(', '.join(exported_functions_by_name)))
        else:
            logging.info('This DLL does not have exported functions')

    def get_pe_dll_exported_functions(self):
        exported_functions_by_name = self.get_exported_functions_by_name()
        return exported_functions_by_name

    def get_export_descriptor_directory_foff(self):
        if self.export_directory_foff:
            return self.export_directory_foff
        export_directory_rva = self.data_directory_info[0]['rva']
        return self._rva_to_file_offset(export_directory_rva)

    def has_exports(self):
        return self.data_directory_info[0]['rva'] != 0

    def get_number_of_functions(self):
        number_of_functions_off = 0x14
        export_directory_foff = self.get_export_descriptor_directory_foff()
        number_of_functions = self._unpack_dword(self.bin_contents, export_directory_foff + number_of_functions_off)
        return number_of_functions

    def get_number_of_names(self):
        number_of_names_off = 0x18
        export_directory_foff = self.get_export_descriptor_directory_foff()
        number_of_names = self._unpack_dword(self.bin_contents, export_directory_foff + number_of_names_off)
        return number_of_names

    def get_exported_functions_by_name(self):
        exported_functions = []
        addr_of_names_foff = self.get_addr_of_names_foff()
        number_of_names = self.get_number_of_names()
        if number_of_names:
            for idx in range(number_of_names):
                exported_name_rva = self._unpack_dword(self.bin_contents, addr_of_names_foff + idx * 4)  # 4 = DWORD
                exported_name_foff = self._rva_to_file_offset(exported_name_rva)
                exported_name_str = self._read_null_terminated_ascii_string(exported_name_foff)
                exported_functions.append(exported_name_str)
        return exported_functions

    def get_addr_of_names_foff(self):
        addr_of_names_offs = 0x20
        export_directory_foff = self.get_export_descriptor_directory_foff()
        addr_of_names_rva = self._unpack_dword(self.bin_contents, export_directory_foff + addr_of_names_offs)
        addr_of_names_foff = self._rva_to_file_offset(addr_of_names_rva)
        return addr_of_names_foff

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


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
