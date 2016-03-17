from struct import unpack, unpack_from
from itertools import zip_longest


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return zip_longest(fillvalue=fillvalue, *args)


def each_bit_in_byte(byte):
    def get_bit(byte, bit_number):
        return (byte & (1 << bit_number)) != 0

    for i in reversed(range(8)):
        yield get_bit(byte, i)


class PivFile(object):
    def __init__(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        self.file_type = unpack('>H', file_data[0:2])
        self.file_length, = unpack('>H', file_data[4:6])
        self.raw_palette = unpack('>32H', file_data[6:6+64])
        self.pixel_data = file_data[6+64:]

        self.extract()

    def extract(self):
        self.extracted_palette = self.extract_palette()
        self.extracted = self.extract_file()

        self.palette = self.extract_palette_2()
        self.pixels = self.extract_pixels()

    def extract_file(self):
        extracted = bytearray()
        offset = 0

        while(offset != self.file_length):
            header_block = unpack_from('>B', self.pixel_data, offset)[0]
            offset += 1

            for copy_previous_sequence in each_bit_in_byte(header_block):
                if copy_previous_sequence:
                    encoded = unpack_from('>H',  self.pixel_data, offset)[0]
                    offset += 2

                    count = 0x22 - ((encoded & 0xf800) >> 11)
                    copy_source = encoded & 0x7ff

                    copy_from = len(extracted) - copy_source
                    new_bytes = extracted[copy_from:copy_from + count]

                    overlapped_bytes = copy_from + count - len(extracted)
                    for extra in range(overlapped_bytes):
                        new_bytes += bytes([new_bytes[extra]])

                    extracted += new_bytes
                else:
                    extracted += unpack_from('>c',  self.pixel_data, offset)[0]
                    offset += 1

                if offset >= self.file_length:
                    break

        return extracted

    def extract_pixels(self):
        memory_width = 40 * 200
        planes = [i * memory_width for i in range(5)]
        output = []

        for i in range(memory_width):
            dh = self.extracted[i]
            dl = self.extracted[planes[1] + i]
            ch = self.extracted[planes[2] + i]
            cl = self.extracted[planes[3] + i]
            ah = self.extracted[planes[4] + i]

            for x in zip(each_bit_in_byte(dh), each_bit_in_byte(dl),
                         each_bit_in_byte(ch), each_bit_in_byte(cl),
                         each_bit_in_byte(ah)):

                al = sum(bit << n for n, bit in enumerate(x))
                output.append(al)

        return output

    def extract_palette(self):
        return [pel & 0x7fff for pel in self.raw_palette]

    def extract_palette_2(self):
        extracted = []
        for pel in self.extracted_palette:
            pel_bytes = pel.to_bytes(2, byteorder='little')

            red = int((pel_bytes[1] << 2) / 64 * 256)
            green = int(((pel_bytes[0] & 0xf0) >> 2) / 64 * 256)
            blue = int(((pel_bytes[0] & 0x0f) << 2) / 64 * 256)

            extracted.append((red, green, blue))

        return extracted
