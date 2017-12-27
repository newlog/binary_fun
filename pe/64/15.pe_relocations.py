#!/usr/bin/env python
import logging
import sys
from libs.pe_generic_utils import PEGenericUtils
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
        self.image_base_relocation_foff = None

    def execute(self, bin_path):
        self.bin_contents = FileUtils.read_file(bin_path)
        if self.bin_contents:
            self.parse_pe32()

    def parse_pe32(self):
        self.pe_section_utils = PESectionUtils(self.bin_contents)
        self.section_headers_info = self.pe_section_utils.get_sections_info()
        self.pe_data_directory_utils = PEDataDirectoryUtils(self.bin_contents)
        self.data_directory_info = self.pe_data_directory_utils.get_data_directories_info()
        self.image_base_relocation_foff = self.get_image_base_relocation_rva()
        max_reloc_rva = self.get_max_rva_for_relocs()
        logging.info('End RVA for relocation information: {}'.format(max_reloc_rva))
        relocation_rvas = self.get_relocation_rvas(max_reloc_rva)
        logging.info('Virtual Addresses where relocations should be applied ({} relocations):'.format(len(relocation_rvas)))
        for reloc_rva in relocation_rvas:
            logging.info('  0x{:x}'.format(reloc_rva))

    def get_image_base_relocation_rva(self):
        if self.image_base_relocation_foff:
            return self.image_base_relocation_foff
        image_base_relocation_rva = self.data_directory_info[5]['rva']
        return image_base_relocation_rva

    def get_max_rva_for_relocs(self):
        return self.get_image_base_relocation_rva() + self.data_directory_info[5]['size']

    def get_relocation_rvas(self, max_reloc_rva):
        relocation_rvas = []
        block_rva = self.get_image_base_relocation_rva()
        while block_rva < max_reloc_rva:
            reloc_rvas_for_block = self.get_relocations_for_block(block_rva)
            relocation_rvas += reloc_rvas_for_block
            block_rva += self.get_block_size(block_rva)
        return relocation_rvas

    def get_relocations_for_block(self, block_rva):
        block_relocs = []
        block_foff = PEGenericUtils.rva_to_file_offset(self.section_headers_info, block_rva)
        block_virtualaddress = self.get_block_virtualaddress(block_rva)
        size_of_block = self.get_block_size(block_rva)
        relocation_block_foff, relocation_foff = block_foff, block_foff + 8
        while relocation_foff < relocation_block_foff + size_of_block:
            reloc_value = self.parse_reloc(relocation_foff)
            if reloc_value:
                block_relocs.append(block_virtualaddress + reloc_value)
            relocation_foff += 2
        return block_relocs

    def get_block_virtualaddress(self, block_rva):
        virtualaddress_off = 0x0
        block_foff = PEGenericUtils.rva_to_file_offset(self.section_headers_info, block_rva)
        size_of_block = PEGenericUtils.unpack_dword(self.bin_contents, block_foff + virtualaddress_off)
        return size_of_block

    def get_block_size(self, block_rva):
        size_of_block_off = 0x4
        block_foff = PEGenericUtils.rva_to_file_offset(self.section_headers_info, block_rva)
        size_of_block = PEGenericUtils.unpack_dword(self.bin_contents, block_foff + size_of_block_off)
        return size_of_block

    def parse_reloc(self, reloc_foff):
        reloc_type_mask = 0b1111000000000000
        reloc_value_mask = 0b0000111111111111
        reloc_word = PEGenericUtils.unpack_word(self.bin_contents, reloc_foff)
        reloc_type = (reloc_word & reloc_type_mask) >> 12
        reloc_value = reloc_word & reloc_value_mask if reloc_type == 0xA else None # PE32+ --> DIR64 is the reloc type
        return reloc_value


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 2:
        parser = ParsePE32()
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path>'.format(sys.argv[0]))
