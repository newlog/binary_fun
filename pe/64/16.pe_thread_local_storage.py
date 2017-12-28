#!/usr/bin/env python
import logging
import sys
from libs.pe_generic_utils import PEGenericUtils
from libs.pe_sections_utils import PESectionUtils
from libs.pe_data_directory_utils import PEDataDirectoryUtils
from libs.pe_optional_header_utils import PEOptionalHeaderUtils


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
        self.pe_optional_header_utils = None
        self.image_tls_directory_foff = None

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        self.pe_section_utils = PESectionUtils(self.bin_contents)
        self.section_headers_info = self.pe_section_utils.get_sections_info()
        self.pe_data_directory_utils = PEDataDirectoryUtils(self.bin_contents)
        self.data_directory_info = self.pe_data_directory_utils.get_data_directories_info()
        self.pe_optional_header_utils = PEOptionalHeaderUtils(self.bin_contents)
        self.image_tls_directory_foff = self.get_image_tls_directory_rva()
        tls_callback_vas = self.get_tls_callbacks()
        logging.info('TLS Callback addresses({} TLS callbacks):'.format(len(tls_callback_vas)))
        for callback_va in tls_callback_vas:
            callback_rva = callback_va - self.pe_optional_header_utils.get_image_base()
            callback_foff = PEGenericUtils.rva_to_file_offset(self.section_headers_info, callback_rva)
            logging.info('  VA: 0x{:x}, RVA: 0x{:x}, File Offset: {}'.format(callback_va, callback_rva, callback_foff))

    def get_image_tls_directory_rva(self):
        tls_rva = self.data_directory_info[9]['rva']
        return tls_rva

    def get_tls_callbacks(self):
        tls_callback_vas = []
        callback_number = 0
        has_more_callbacks = True
        while has_more_callbacks:
            address_of_callbacks_va = self.get_address_of_callbacks_va(callback_number)
            # PE32+: Looks like in PE32+ we still need to check only a DWORD and not a QWORD, so we read a QWORD
            # as we do to get the callback address, but we clean up the MSBytes. If the LSBytes are 0, end of callbacks
            has_more_callbacks = address_of_callbacks_va & 0x000000FFFFFFFF != 0x0
            if has_more_callbacks:
                tls_callback_vas.append(address_of_callbacks_va)
                callback_number += 1
        return tls_callback_vas

    def get_address_of_callbacks_va(self, callback_number):
        address_of_callbacks_off = 24 + callback_number * 8  # PE32+: fix offset and increase to sizeof(QWORD)
        image_tls_directory_rva = self.get_image_tls_directory_rva()
        image_tls_directory_foff = PEGenericUtils.rva_to_file_offset(self.section_headers_info, image_tls_directory_rva)
        address_of_callbacks_va = PEGenericUtils.unpack_qword(self.bin_contents, image_tls_directory_foff + address_of_callbacks_off)  # PE32+: Unpack QWORD
        return address_of_callbacks_va


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
