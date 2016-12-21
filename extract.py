from itertools import zip_longest
from struct import unpack, unpack_from


class CompressedFile(object):
    def __init__(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()

    def get_header_length(self, file_data):
        return unpack('>H', file_data[0:2])[0] * 10 + 10


def each_bit_in_byte(byte):
    def get_bit(byte, bit_number):
        return (byte & (1 << bit_number)) != 0

    for i in reversed(range(8)):
        yield get_bit(byte, i)


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return zip_longest(fillvalue=fillvalue, *args)


def extract_file(file_length, file_data):
    extracted = bytearray()
    offset = 0

    while(offset != file_length):
        header_block = unpack_from('>B', file_data, offset)[0]
        offset += 1

        for copy_previous_sequence in each_bit_in_byte(header_block):
            if copy_previous_sequence:
                encoded = unpack_from('>H',  file_data, offset)[0]
                offset += 2

                count = 0x22 - ((encoded & 0xf800) >> 11)
                copy_source = encoded & 0x7ff

                copy_from = len(extracted) - copy_source
                new_bytes = extracted[copy_from:copy_from + count]

                overlapped_bytes = copy_from + count - len(extracted)
                for extra in range(overlapped_bytes):
                    new_bytes.append(new_bytes[extra])

                extracted += new_bytes
            else:
                extracted += unpack_from('>c',  file_data, offset)[0]
                offset += 1

            if offset >= file_length:
                break

    return extracted


def extract_palette(palette_data, base=64):
    def extract_rgb(pel):
        pel_bytes = pel.to_bytes(2, byteorder='little')

        red = int((pel_bytes[1] << 2) / 64 * base)
        green = int(((pel_bytes[0] & 0xf0) >> 2) / 64 * base)
        blue = int(((pel_bytes[0] & 0x0f) << 2) / 64 * base)

        return red, green, blue

    return [extract_rgb(i) for i in palette_data]
