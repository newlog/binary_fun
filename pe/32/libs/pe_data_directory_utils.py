import struct
import logging


class PEDataDirectoryUtils(object):
    """
    PE/PE32+,Size,Field,Description
    96/112,8,Export Table,Export Table address and size.
    104/120,8,Import Table,Import Table address and size
    112/128,8,Resource Table,Resource Table address and size.
    120/136,8,Exception Table,Exception Table address and size.
    128/144,8,Certificate Table,Attribute Certificate Table address and size.
    136/152,8,Base Relocation Table,Base Relocation Table address and size.
    144/160,8,Debug,Debug data starting address and size.
    152/168,8,Architecture,Architecture-specific data address and size.
    160/176,8,Global Ptr,Relative virtual address of the value to be stored in the global pointer register. Size member of this structure must be set to 0.
    168/184,8,TLS Table,Thread Local Storage (TLS) Table address and size.
    176/192,8,Load Config,Table Load Configuration Table address and size.
    184/200,8,Bound Import,Bound Import Table address and size.
    192/208,8,IAT,Import Address Table address and size.
    200/216,8,Delay Import Descriptor,Address and size of the Delay Import Descriptor.
    208/224,8,COM+ Runtime Header,COM+ Runtime Header address and size
    216/232,8,Reserved
    """

    def __init__(self, bin_contents):
        self.bin_contents = bin_contents
        self.image_dos_header_offs = 0
        self.pe_header_offs = self.get_pe_header_offs()
        self.optional_header_offs = self.get_optional_header_offs()
        self.data_directories_array_offs = self.get_data_directory_array_offs()
        self.number_of_rva_and_sizes = self.get_number_of_rva_and_sizes()
        self.data_directory_info = []

    def get_data_directories_info(self):
        if self.data_directory_info:
            return self.data_directory_info
        data_directory_entries = ['Export Table', 'Import Table', 'Resource Table', 'Exception Table', 'Certificate Table', 'Base Relocation Table', 'Debug', 'Architecture', 'Global Ptr', 'TLS Table', 'Load Config', 'Bound Import', 'IAT', 'Delay Import Descriptor', 'COM+ Runtime Header', 'Reserved']
        for idx,data_directory_entry in enumerate(data_directory_entries):
            if idx < self.number_of_rva_and_sizes:
                item = {'name': data_directory_entry, 'rva': self.get_data_directory_entry_virtual_address(idx), 'size': self.get_data_directory_entry_size(idx)}
                self.data_directory_info.append(item)
            else:
                logging.warning('PE Header specifies less data directory entries than expected. Max Number: {}. Expected: 16. Ignoring remaining entries.'.format(self.number_of_rva_and_sizes))
        return self.data_directory_info

    def get_number_of_rva_and_sizes(self):
        number_of_rva_and_sizes_offs = 0x5C
        optional_header_offs = self.optional_header_offs
        self.number_of_rva_and_sizes = self._unpack_dword(optional_header_offs + number_of_rva_and_sizes_offs)
        return self.number_of_rva_and_sizes

    def get_data_directory_entry_virtual_address(self, index):
        rva_offs = 0x0
        data_directory_entry_offs = self.get_specific_data_directory_entry_offs(index)
        rva = self._unpack_dword(data_directory_entry_offs + rva_offs)
        return rva

    def get_data_directory_entry_size(self, index):
        size_offs = 0x4
        data_directory_entry_offs = self.get_specific_data_directory_entry_offs(index)
        size = self._unpack_dword(data_directory_entry_offs + size_offs)
        return size

    def get_specific_data_directory_entry_offs(self, index):  # IMAGE_DIRECTORY_ENTRY_IMPORT (DataDirectory[index])
        data_directory_array_offs = self.data_directories_array_offs
        image_data_directory_size = 0x8  # two dwords
        return data_directory_array_offs + image_data_directory_size * index

    def get_data_directory_array_offs(self):  # _IMAGE_DATA_DIRECTORY DataDirectory[16]; from OptionalHeader
        optional_header_offs = self.optional_header_offs
        data_directories_array_offs = optional_header_offs + 0x60
        return data_directories_array_offs

    def get_pe_header_offs(self):
        e_lfanew_offs = 0x3C
        pe_header_offs = self._unpack_dword(self.image_dos_header_offs + e_lfanew_offs)
        self.pe_header_offs = pe_header_offs
        return self.pe_header_offs

    def get_optional_header_offs(self):
        self.optional_header_offs = self.pe_header_offs + 0x18
        return self.optional_header_offs

    def _unpack_dword(self, offs):
        # format string: <: little endian. L: 4 bytes (1 dword)
        return struct.unpack_from('<L', self.bin_contents, offs)[0]
