#!/usr/bin/env python
import struct
import logging
import sys
import os
import shutil


def str_to_int(string_number):
    value = None
    bases = [10, 16]
    for base in bases:
        try:
            value = int(string_number, base)
        except ValueError:
            pass
    if not value:
        raise ValueError('"{}" could not be converted to int using any of the following bases: {}'.format(string_number, bases))
    return value


class FileUtils(object):

    def write_to_new_file(self, in_path, string, offs, out_path=None):
        success = False
        file_contents = self.read_file(in_path)
        if file_contents:
            new_file_contents = file_contents[:offs] + string + file_contents[offs + len(string):]
            out_file_path = out_path if out_path else in_path + '_new'
            success = self.write_file(out_file_path, new_file_contents, 0)
        return success

    @staticmethod
    def read_file(path):
        file_contents = None
        try:
            with open(path, 'rb') as fd:
                file_contents = fd.read()
        except IOError as e:
            logging.error('Error reading file "{}". Error: {}'.format(path, e))
        return file_contents

    @staticmethod
    def write_file(path, string, offs):
        success = True
        try:
            with open(path, 'wb') as fd:
                fd.seek(offs)
                fd.write(string)
        except IOError as e:
            logging.error('Error writing file "{}". Error: {}'.format(path, e))
            success = False
        return success

    @staticmethod
    def copy_file(in_path, out_path=None):
        out_file_path = out_path if out_path else in_path + '_new'
        try:
            shutil.copyfile(in_path, os.path.abspath(out_file_path))
        except IOError as e:
            logging.error('File "{}" could not be copied to "{}". Error: {}'.format(in_path, out_file_path, e))
        return out_file_path


class TamperBinary(object):

    def __init__(self, string, offset):
        """
        You can use this class to write strings that will be written in a file starting at a given offset.
        The file modifications will be saved into a new file in the same directory.

        For example, for a PE you can pass string "GOD" and byte offset  0x6C to modify the string:
          This program cannot be run in DOS mode
        to
          This program cannot be run in GOD mode

        :param string: String to be written.
        :param offset: Offset where the string will be written. Offset starts at 0.
        """
        self.string = string
        self.offset = offset

    def execute(self, bin_path):
        fu = FileUtils()
        if fu.write_to_new_file(bin_path, self.string, int(self.offset)):
            logging.info('Binary successfully modified. String "{}" written starting at byte offset {}'.format(self.string, self.offset))
        else:
            logging.info('Failed to modify binary.')


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 4:
        parser = TamperBinary(sys.argv[2], str_to_int(sys.argv[3]))
        parser.execute(sys.argv[1])
    else:
        logging.error('Usage: {} <file_path> <string> <offset>'.format(sys.argv[0]))
