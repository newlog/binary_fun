import struct
from collections import OrderedDict


class PESectionUtils(object):

    def __init__(self, bin_contents):
        self.bin_contents = bin_contents
        self.number_of_sections = None
        self.image_dos_header_offs = 0
        self.file_header_offs = None
        self.pe_header_offs = None
        self.optional_header_offs = None

    def get_sections_info(self):
        section_headers_info = []
        optional_header_size = self.get_file_header_optional_header_size()
        num_of_sections = self.get_fileheader_num_of_sections()
        section_headers_offs = self.get_optional_header_offs() + optional_header_size
        for section_header_num in range(num_of_sections):
            section_headers_info.append(self.get_section_info(section_headers_offs, section_header_num))
        return section_headers_info

    def get_fileheader_num_of_sections(self):
        if self.number_of_sections:
            return self.number_of_sections
        self.file_header_offs = self.get_file_header_offs()
        num_of_sections_offs = 0x2
        num_of_sections_value = self._unpack_word(self.file_header_offs + num_of_sections_offs)
        return num_of_sections_value

    def get_file_header_offs(self):
        if self.file_header_offs:
            return self.file_header_offs
        return self.get_pe_header_offs() + 0x4

    def get_pe_header_offs(self):
        if self.pe_header_offs:
            return self.pe_header_offs
        e_lfanew_offs = 0x3C
        pe_header_offs = self._unpack_dword(self.image_dos_header_offs + e_lfanew_offs)
        self.pe_header_offs = pe_header_offs
        return self.pe_header_offs

    def get_file_header_optional_header_size(self):
        self.file_header_offs = self.get_file_header_offs()
        optional_header_size_offs = 0x10
        size_of_optional_header = self._unpack_word(self.file_header_offs + optional_header_size_offs)
        return size_of_optional_header

    def get_optional_header_offs(self):
        if self.optional_header_offs:
            return self.optional_header_offs
        self.optional_header_offs = self.get_pe_header_offs() + 0x18
        return self.optional_header_offs

    def get_section_info(self, section_headers_offs, section_header_num):
        section_header_info = OrderedDict({})
        header_size = 0x24 + 4  # +4 comes from sizeof(IMAGE_SECTION_HEADER.Characteristics) = sizeof(1 dword) = 4 bytes
        section_header_offs = section_headers_offs + header_size * section_header_num
        section_header_info['Name'] = self.get_section_name(section_header_offs)
        section_header_info['Virtual Size'] = self.get_section_virtual_size(section_header_offs)
        section_header_info['Virtual Address'] = self.get_section_virtual_address(section_header_offs)
        section_header_info['Size of Raw Data'] = self.get_section_size_of_raw_data(section_header_offs)
        section_header_info['Pointer to Raw Data'] = self.get_section_pointer_to_raw_data(section_header_offs)
        return section_header_info

    def get_section_name(self, section_header_offs):
        section_name = self._unpack_qword_big_endian(section_header_offs)
        section_name = self._bytes_to_string(section_name, 8)
        return section_name

    def get_section_virtual_size(self, section_header_offs):
        virtual_size_offs = section_header_offs + 0x8
        virtual_size = self._unpack_dword(virtual_size_offs)
        return virtual_size

    def get_section_virtual_address(self, section_header_offs):
        virtual_address_offs = section_header_offs + 0xc
        virtual_size = self._unpack_dword(virtual_address_offs)
        return virtual_size

    def get_section_size_of_raw_data(self, section_header_offs):
        size_of_raw_data_offs = section_header_offs + 0x10
        virtual_size = self._unpack_dword(size_of_raw_data_offs)
        return virtual_size

    def get_section_pointer_to_raw_data(self, section_header_offs):
        pointer_to_raw_data_offs = section_header_offs + 0x14
        virtual_size = self._unpack_dword(pointer_to_raw_data_offs)
        return virtual_size

    @staticmethod
    def _bytes_to_string(value, length):
        # https://gph.is/1KjihQe (https://stackoverflow.com/questions/3673428/convert-int-to-ascii-and-back-in-python)
        return ''.join(chr((value >> 8 * (length - byte - 1)) & 0xFF) for byte in range(length))

    def _unpack_qword_big_endian(self, offs):
        # format string: >: big endian. Q: 8 bytes (2 dwords)
        return struct.unpack_from('>Q', self.bin_contents, offs)[0]

    def _unpack_dword(self, offs):
        # format string: <: little endian. L: 4 bytes (1 dword)
        return struct.unpack_from('<L', self.bin_contents, offs)[0]

    def _unpack_word(self, offs):
        # format string: <: little endian. H: 2 bytes (1 word)
        return struct.unpack_from('<H', self.bin_contents, offs)[0]
