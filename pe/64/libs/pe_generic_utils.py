import struct


class PEGenericUtils(object):

    @staticmethod
    def read_null_terminated_ascii_string(self, bin_contents, starting_addr):
        idx = 0
        ascii_string = ''
        while ord(bin_contents[starting_addr + idx]) != 0 and starting_addr + idx < len(bin_contents):
            ascii_string += bin_contents[starting_addr + idx]
            idx += 1
        return ascii_string

    @staticmethod
    def rva_to_file_offset(section_headers_info, rva):
        file_offs = -1
        for section_info in section_headers_info:
            if PEGenericUtils.rva_belongs_to_section(rva, section_info):
                file_offs = rva - section_info['Virtual Address'] + section_info['Pointer to Raw Data']
                break
        return file_offs

    @staticmethod
    def rva_belongs_to_section(rva, section_info):
        return section_info['Virtual Address'] <= rva < section_info['Virtual Address'] + section_info['Virtual Size']

    @staticmethod
    def bytes_to_string(value, length):
        # https://gph.is/1KjihQe (https://stackoverflow.com/questions/3673428/convert-int-to-ascii-and-back-in-python)
        return ''.join(chr((value >> 8 * (length - byte - 1)) & 0xFF) for byte in range(length))

    @staticmethod
    def unpack_qword_big_endian(contents, offs):
        # format string: >: big endian. Q: 8 bytes (2 dwords)
        return struct.unpack_from('>Q', contents, offs)[0]

    @staticmethod
    def unpack_qword(contents, offs):
        # format string: <: little endian. Q: 8 bytes (2 dwords)
        return struct.unpack_from('<Q', contents, offs)[0]

    @staticmethod
    def unpack_dword(contents, offs):
        # format string: <: little endian. L: 4 bytes (1 dword)
        return struct.unpack_from('<L', contents, offs)[0]

    @staticmethod
    def unpack_word(contents, offs):
        # format string: <: little endian. H: 2 bytes (1 word)
        return struct.unpack_from('<H', contents, offs)[0]