import os
import sys
from collections import namedtuple
from enum import IntFlag
from struct import iter_unpack, unpack

import pygame
from attr import attrs, attrib

from extract import each_bit_in_byte, extract_file, grouper
# from cli import print_hex_view
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

ImageDimension = namedtuple('ImageDimension',
                            'width, height, x_offset, y_offset')
ImageHeader = namedtuple('ImageHeader', ['padding', 'data_address',
                                         'width', 'height',
                                         'x_adjust', 'blit_type'])
SubimageMetadata = namedtuple('SubimageMetadata', 'dimension, is_fullscreen')


def sum_bits(bits, bit_mask=0):
    '''Calculate byte from bit values and bit positions

    args:
        bits (list of bool): binary values for each position.
        bit_mask (int): values of bits we want to sum

    returns (int/byte): byte value
    '''

    original_byte = sum(bit << x for x, bit in enumerate(bits))
    return original_byte & bit_mask


def sum_bits_duplicates(bits, duplicate_position=4, bit_mask=None):
    '''Calculate byte from bit values and bit positions

    args:
        bit_mask (list of ints): each int represents the position of its
            respective bit value in bits. e.g [3, 4] indicates the first and
            second element of bits should be shifted to the third and forth
            positon of the final byte output.
        bits (list of bool): binary values for each position.
        duplicate_position (int): The bit in duplicate position is the ORed
            value of all of bit positions. e.g bit_mask=[0, 1],
            duplicate_position=4 indicates that bit 4 in the final byte should
            be bit 0 | bit 1 of the final byte.

    returns (int/byte): byte value
    '''
    if bit_mask is None:
        bit_mask = [0, 1]

    total = sum(
        bit << bit_mask[bit_pos] for bit_pos, bit in enumerate(bits)
    )
    duplicate = any(bits) << duplicate_position
    total += duplicate
    return total


def recombine(blit_type, bit_planes, length):
    output = [None] * (length * 8)
    o = len(output)

    if blit_type == 32:
        blit_function = sum_bits_duplicates
    else:
        blit_function = sum_bits

    # get the nth byte of every bit_plane
    for i, bytes_list in enumerate(zip(*bit_planes)):
        # get the nth set of bits of those bytes
        as_bits = [each_bit_in_byte(byte) for byte in bytes_list]

        for j, bits in enumerate(zip(*as_bits)):
            # reconstruct the output byte from those bits
            output[i * 8 + j] = blit_function(bits=bits,
                                              bit_mask=blit_type)

    assert o == len(output)
    return output


# def draw_string(font, text, y, main_exe):
#     image_numbers = []
#     image_widths = []
#     ords = []
#     for char in text:
#         image_number = main_exe.bold_f_char_lookup[ord(char) - 0x20]
#         ords.append(ord(char))
#         image_numbers.append(image_number)
#         # meta = main_exe.strings[text]
#         image_widths.append(font.get_image_width(image_number, bordered=True))
#
#     screen_dimensions = main_exe.screen_dimensions
#     image_width = sum(image_widths)
#     center = int(((screen_dimensions.right - screen_dimensions.left) -
#                   image_width) / 2)
#
#     for i, w in zip(image_numbers, image_widths):
#         #font.extract_subimage(piv, i, center, y)
#         center += w
#     print(f"draw_string {text}", image_widths, image_numbers)


class FontFile(object):
    def __init__(self, file_data):
        self.image_count = unpack('>H', file_data[0:2])[0]
        self.header_length = self.image_count * 10 + 10

        self.file_length = unpack('>H', file_data[4:6])[0]
        self.file_data = file_data[self.header_length:]

        header_data = file_data[10:self.header_length]
        self.headers = [ImageHeader(*xs)
                        for xs in iter_unpack('>4H2B', header_data)]

        self.extracted = extract_file(self.file_length, self.file_data)

        self.images = [
            Image.from_data(header, self.extracted)
            for header in self.headers
        ]
        #print("number of subimages: {}".format(self.image_count))

    #def get_image_height(self, image_number):
    #    return self.headers[image_number].height

    #def get_image_width(self, image_number, bordered=None):
    #    image_width = self.headers[image_number].width
        # if dx & 8 width:
        # test = (((image_width + 0xf) & 0xfff0) >> 4) << 1
     #   if bordered:
     #       image_width -= 3
     #   return image_width

    # def extract_subimage(self, piv, image_number, x_offset, y_offset):
    #     header = self.headers[image_number]
    #
    #     image_data_location = header.data_address + self.header_length
    #
    #     image_width = header.width + 15
    #     packed_image_width = image_width // 16 * 2
    #     image_height = header.height
    #
    #     x_offset_adjust = header.x_adjust >> 4
    #     x_offset -= x_offset_adjust
    #
    #     packed_image_length = packed_image_width * image_height
    #     bit_planes = [image_data_location + (packed_image_length * i)
    #                   for i in range(0, 5)]
    #
    #     pixels = self.recombine(
    #         image_number,
    #         header.blit_type,
    #         bit_planes,
    #         packed_image_length
    #     )
    #
    #     unpacked_image_width = packed_image_width * 8
    #
    #     return Image(
    #         width=unpacked_image_width,
    #         height=image_height,
    #         x_adjust=x_offset_adjust,
    #         piv=piv,
    #         pixels=pixels
    #     )

        # packed_image_width <<= 3

        #print("width", image_width, packed_image_width, unpacked_image_width)

        # image_offset = self.compare_image_width(
        #         x_offset=x_offset,
        #         image_width=unpacked_image_width
        # )

        #if image_offset:
        #    unpacked_image_width = image_offset[1]

        # return SubimageMetadata(
        #     ImageDimension(image_width, image_height, x_offset, y_offset),
        #     is_fullscreen,
        # )

        # self.blit(
        #     piv,
        #     y_offset,
        #     x_offset=x_offset,
        #     image_height=image_height,
        #     #image_width=image_width,
        #     image_width=unpacked_image_width,
        #     is_fullscreen=self.is_fullscreen(unpacked_image_width)
        # )

    def recombine(self, image_num, blit_type, bit_plane_positions, length):
        output = [None] * (length * 8)
        o = len(output)

        bit_planes = []
        if blit_type == 32:
            bit_length = 2
            blit_function = sum_bits_duplicates
        else:
            bit_length = blit_type.bit_length()
            blit_function = sum_bits

        for position in bit_plane_positions[0:bit_length]:
            pos = position - self.header_length
            bit_planes.append(self.extracted[pos:pos + length])

        #import ipdb; ipdb.set_trace()
        #bit_planes = self.images[image_num]
        # get the nth byte of every bit_plane
        for i, bytes_list in enumerate(zip(*bit_planes)):
            # get the nth set of bits of those bytes
            as_bits = [each_bit_in_byte(byte) for byte in bytes_list]

            for j, bits in enumerate(zip(*as_bits)):
                # reconstruct the output byte from those bits
                output[i * 8 + j] = blit_function(bits=bits,
                                                  bit_mask=blit_type)

        assert o == len(output)
        return output

    # def sub_7969(self, y_offset):
    #     if y_offset < 0:
    #         pass
    #
    # def compare_image_width(self, x_offset, image_width):
    #     total = x_offset + image_width
    #     if total > SCREEN_WIDTH and x_offset < SCREEN_WIDTH:
    #         overrun = total - SCREEN_WIDTH
    #         return overrun, image_width - overrun
    #
    # def is_fullscreen(self, unpacked_image_width):
    #     print("is_fullscreen", unpacked_image_width & 0x0003)
    #     return unpacked_image_width & 0x0003
    #
    # def blit(self, piv, y_offset, x_offset, image_height, image_width,
    #          is_fullscreen):
    #     src = 0
    #     print("is fullscreen", is_fullscreen)
    #     if is_fullscreen:
    #         first_pass = True
    #     else:
    #         first_pass = False
    #
    #     for y in range(image_height):
    #         if first_pass:
    #             dest = (y + y_offset) * 320 + x_offset
    #             # image_width = 320
    #         else:
    #             dest = (y + y_offset) * 320 + x_offset
    #         for x in range(image_width):
    #             if self.pixels[src] != 0:
    #                 piv.pixels[dest] = self.pixels[src]
    #             # piv.pixels[dest] = self.pixels[src]
    #             dest += 1
    #             src += 1
    #         first_pass = False


@attrs
class Image(object):
    width = attrib()
    height = attrib()
    x_adjust = attrib()
    pixels = attrib()

    @classmethod
    def from_data(cls, header, extracted):
        packed_image_width = (header.width + 15) // 16 * 2
        if header.blit_type == 32:
            num_bit_planes = 2
        else:
            num_bit_planes = header.blit_type.bit_length()
        bit_plane_length = packed_image_width * header.height

        bit_planes = []
        for i in range(num_bit_planes):
            start = header.data_address + (i * bit_plane_length)
            stop = start + bit_plane_length
            bit_planes.append(extracted[start:stop])

        unpacked_image_width = packed_image_width * 8

        x_offset_adjust = header.x_adjust >> 4
        #x_offset -= x_offset_adjust

        pixels = recombine(header.blit_type, bit_planes, unpacked_image_width * header.height)

        return cls(unpacked_image_width, header.height, x_offset_adjust, pixels)

    def to_surface(self, palette):
        return pixel_to_surface(self.width, self.height, self.pixels, palette)


def pixel_to_surface(width, height, pixels, palette):
    surface = pygame.Surface((width, height), pygame.SRCALPHA)
    pixel_array = pygame.PixelArray(surface)

    for y, line in enumerate(grouper(pixels, width)):
        for x, pixel in enumerate(line):
            if pixel:
                pixel_array[x, y] = palette[pixel]

    del pixel_array
    return surface


class StringFlag(IntFlag):
    centered = 1
    right_justified = 4
    bordered = 8


@attrs
class String():
    x = attrib()
    y = attrib()
    text = attrib()
    flags = attrib()
    font = attrib()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: view.arg <filename> <piv file>")
        sys.exit()

    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             sys.argv[1])
    with open(file_path, 'rb') as f:
        font = FontFile(f.read())
    # print(hex(font.file_length))
    # print(hex(font.header_length))

    # print_hex_view(font.extracted)
    # print_hex_view(font.header)
    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             sys.argv[2])
    with open(file_path, 'rb') as f:
        piv = PivFile(f.read())

    for i in range(320):
        test = (((i + 0xf) & 0xfff0) >> 4) << 1
        print(i, test)