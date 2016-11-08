import pdb
from pprint import pprint


from collections import namedtuple
import os, sys
from struct import unpack, iter_unpack
from extract import extract_file, each_bit_in_byte
from cli import print_hex_view
from piv import PivFile

# 4ce4:5ba7
ds_8178 = {
    0x8178: 0x11,
    0x8179: 0x22,
    0x817a: 0x44,
    0x817b: 0x88,
}

SCREEN_WIDTH = 320
SCREEN_HEIGHT = 200

ImageDimension = namedtuple('ImageDimension', 'width, height, x_offset, y_offset')
ImageHeader = namedtuple('ImageHeader', ['padding', 'data_address',
                                         'width', 'height',
                                         'x_adjust', 'blit_type'])
SubimageMetadata = namedtuple('SubimageMetadata', 'dimension, is_fullscreen')

def sum_bits(bit_positions, bits):
    '''Calculate byte from bit values and bit positions

    args:
        bit_positions (list of ints): each int represents the position of its
            respective bit value in bits. e.g [3, 4] indicates the first and
            second element of bits should be shifted to the third and forth
            positon of the final byte output.
        bits (list of bool): binary values for each position.

    returns (int/byte): byte value
    '''
    return sum(bit << bit_positions[bit_pos] for bit_pos, bit in enumerate(bits))


def sum_bits_duplicate(bit_positions, duplicate_position, bits):
    '''Similar to sum bits, with a duplicate

    The bit in duplicate position is the ORed value of all of bit positions. e.g
    bit_positions=[0, 1], duplicate_position=4 indicates that bit 4 in the final
    byte should be bit 0 | bit 1 of the final byte.
    '''
    total = sum(bit << bit_positions[bit_pos] for bit_pos, bit in enumerate(bits))
    duplicate = any(bits) << duplicate_position
    total += duplicate
    return total


blit_function_table = {
    1: (sum_bits, [0]),
    3: (sum_bits, [0, 1]),
    4: (sum_bits, [2]),
    5: (sum_bits, [0, 2]),
    6: (sum_bits, [1, 2]),
    7: (sum_bits, [0, 1, 2]),
    9: (sum_bits, [0, 3]),
    10: (sum_bits, [1, 3]),
    11: (sum_bits, [0, 1, 3]),
    12: (sum_bits, [2, 3]),
    13: (sum_bits, [0, 2, 3]),
    14: (sum_bits, [1, 2, 3]),
    15: (sum_bits, [0, 1, 2, 3]),
    16: (sum_bits, [4]),
    18: (sum_bits, [1, 4]),
    19: (sum_bits, [0, 1, 4]),
    23: (sum_bits, [0, 1, 2, 4]),
    27: (sum_bits, [0, 1, 3, 4]),
    28: (sum_bits, [2, 3, 4]),
    30: (sum_bits, [1, 2, 3, 4]),
    31: (sum_bits, [0, 1, 2, 3, 4]),
    32: (sum_bits_duplicate, [0, 1], 4),
}


def draw_string(piv, font, text, y, main_exe):
    image_numbers = []
    image_widths = []
    ords = []
    for char in text:
        image_number = main_exe.bold_f_char_lookup[ord(char) - 0x20]
        ords.append(ord(char))
        image_numbers.append(image_number)
        meta = main_exe.strings[text]
        image_widths.append(font.get_image_width(image_number, bordered=True))

    screen_dimensions = main_exe.screen_dimensions
    image_width = sum(image_widths)
    center = int(((screen_dimensions.right - screen_dimensions.left) - image_width) / 2)

    for i, w in zip(image_numbers, image_widths):
        font.extract_subimage(piv, i, center, y)
        center += w


class NotValidSubimage(Exception):
    pass


class FontFile(object):
    def __init__(self, file_data):
        self.image_count = unpack('>H', file_data[0:2])[0]
        self.header_length = self.image_count * 10 + 10

        self.file_length = unpack('>H', file_data[4:6])[0]
        self.file_data = file_data[self.header_length:]

        header_data = file_data[10:self.header_length]
        self.headers = [ImageHeader(*xs) for xs in iter_unpack('>4H2B', header_data)]

        self.extracted = extract_file(self.file_length, self.file_data)

        self.images = []
        for header in self.headers:
            packed_image_width = header.width // 16 * 2
            num_bit_planes = 4
            image_length = packed_image_width * header.height * num_bit_planes
            image_data = self.extracted[header.data_address:header.data_address+image_length]
            self.images.append(image_data)

    def get_image_height(self, image_number):
        return self.headers[image_number].height

    def get_image_width(self, image_number, bordered=None):
        image_width = self.headers[image_number].width
        # if dx & 8 width:
        test = (((image_width + 0xf) & 0xfff0) >> 4) << 1
        if bordered:
            image_width -= 3
        return image_width

    def extract_subimage(self, piv, image_number, x_offset, y_offset):
        try:
            header = self.headers[image_number]
        except KeyError:
            raise NotValidSubimage(
                '{} is not in the range [0, {}]'.format(image_number,
                                                        self.image_count)
            )
        if not header.blit_type:
            return

        image_data_location = header.data_address + self.header_length

        image_width = header.width + 0xf
        packed_image_width = image_width // 16 * 2
        image_height = header.height

        x_offset_adjust = header.x_adjust >> 4
        x_offset -= x_offset_adjust

        packed_image_length = packed_image_width * image_height
        bit_planes =  [image_data_location + (packed_image_length * i)
                       for i in range(0, 5)]

        self.pixels = self.recombine(header.blit_type, bit_planes,
                                     packed_image_length)

        unpacked_image_width = packed_image_width * 8
        #packed_image_width <<= 3

        image_offset = self.compare_image_width(
                x_offset=x_offset,
                image_width=unpacked_image_width
        )

        if image_offset:
            unpacked_image_width = image_offset[1]

    
        #return SubimageMetadata(
        #    ImageDimension(image_width, image_height, x_offset, y_offset),
        #    is_fullscreen,
        #)

        self.blit(
            piv,
            y_offset,
            x_offset=x_offset,
            image_height=image_height,
            image_width=unpacked_image_width,
            is_fullscreen=self.is_fullscreen(unpacked_image_width)
        )

    def recombine(self, blit_type, bit_plane_positions, length):
        output = [None] * (length * 8)
        o = len(output)

        bit_planes = []
        sum_func, bit_positions = blit_function_table[blit_type]
        for _, position in zip(bit_positions, bit_plane_positions):
            pos = position - self.header_length
            bit_planes.append(self.extracted[pos:pos + length]) 


        # get the nth byte of every bit_plane
        for i, bytes_list in enumerate(zip(*bit_planes)):
            # get the nth set of bits of those bytes
            for j, bits in enumerate(zip(*[each_bit_in_byte(byte) for byte in bytes_list])):
                # reconstruct the output byte from those bits
                output[i * 8 + j] = sum_func(bit_positions, bits)

        assert o == len(output)
        return output

    def sub_7969(self, y_offset):
        if y_offset < 0:
            pass

    def compare_image_width(self, x_offset, image_width):
        total = x_offset + image_width
        if total > SCREEN_WIDTH and x_offset < SCREEN_WIDTH:
            overrun = total - SCREEN_WIDTH
            return overrun, image_width - overrun

    def is_fullscreen(self, unpacked_image_width):
        return unpacked_image_width & 0x0003

    def blit(self, piv, y_offset, x_offset, image_height, image_width, is_fullscreen):
        src = 0
        first_pass = True

        for y in range(image_height):
            if is_fullscreen and not first_pass:
                dest = (y + y_offset) * 320
                image_width = 320
            else:
                dest = (y + y_offset) * 320 + x_offset
            for x in range(image_width):
                if self.pixels[src] != 0:
                    piv.pixels[dest] = self.pixels[src]
                #piv.pixels[dest] = self.pixels[src]
                dest += 1
                src += 1
            first_pass = False


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: view.arg <filename> <piv file>")
        sys.exit()

    file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           sys.argv[1])
    with open(file_path, 'rb') as f:
        font = FontFile(f.read())
    #print(hex(font.file_length))
    #print(hex(font.header_length))

    #print_hex_view(font.extracted)
    #print_hex_view(font.header)
    file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           sys.argv[2])
    with open(file_path, 'rb') as f:
        piv = PivFile(f.read())

    for i in range(320):
        test = (((i + 0xf) & 0xfff0) >> 4) << 1
        print(i, test)
