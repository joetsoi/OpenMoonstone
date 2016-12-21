from itertools import repeat
from struct import unpack

from extract import each_bit_in_byte, extract_file, extract_palette


class PivFile(object):
    def __init__(self, file_data):
        self.file_type = unpack('>H', file_data[0:2])[0]
        self.file_length = unpack('>H', file_data[4:6])[0]
        if self.file_type == 5:
            self.raw_palette = unpack('>32H', file_data[6:6+64])
            self.pixel_data = file_data[6+64:]
        elif self.file_type == 4:
            self.raw_palette = unpack('>16H', file_data[6:6+32])
            self.pixel_data = file_data[6+32:]
        else:
            raise ValueError(
                'Does not appear to be a valid piv file,'
                'valid types are 4 or 5, got {}'.format(self.file_type)
            )

        self.extract()

    def extract(self):
        self.extracted_palette = self.extract_palette()
        self.extracted = extract_file(self.file_length, self.pixel_data)

        padding = 40000 - len(self.extracted)
        if padding > 0:
            trailing_zeroes = bytearray(repeat(0, padding))
            self.extracted += trailing_zeroes

        self.palette = extract_palette(self.extracted_palette, base=256)
        self.pixels = self.extract_pixels()

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
