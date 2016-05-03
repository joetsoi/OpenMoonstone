from struct import unpack, unpack_from
from itertools import repeat
from extract import extract_file, each_bit_in_byte, grouper



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

        self.extract()

    def extract(self):
        self.extracted_palette = self.extract_palette()
        extracted = extract_file(self.file_length, self.pixel_data)
        self.extracted = extracted + bytearray(repeat(0, 40000 - len(extracted)))
        #print("blah", len(self.extracted))

        self.palette = self.extract_palette_2()
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

    def extract_palette_2(self):
        extracted = []
        for pel in self.extracted_palette:
            pel_bytes = pel.to_bytes(2, byteorder='little')

            #red = pel_bytes[1] << 2
            #green = (pel_bytes[0] & 0xf0) >> 2
            #blue = (pel_bytes[0] & 0x0f) << 2

            red = int((pel_bytes[1] << 2) / 64 * 256)
            green = int(((pel_bytes[0] & 0xf0) >> 2) / 64 * 256)
            blue = int(((pel_bytes[0] & 0x0f) << 2) / 64 * 256)

            extracted.append((red, green, blue))

        return extracted
