import pdb
from pprint import pprint


from collections import namedtuple
from functools import partial
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
    duplicate = any(bit_positions) << duplicate_position
    total += duplicate


blit_function_table = {
    1: partial(sum_bits, [0]),
    3: partial(sum_bits, [0, 1]),
    7: partial(sum_bits, [0, 1, 2]),
    15: partial(sum_bits, [0, 1, 2, 3]),
    30: partial(sum_bits, [1, 2, 3, 4]),
    31: partial(sum_bits, [0, 1, 2, 3, 4]),
    32: partial(sum_bits_duplicate, [0, 1], 4),
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


class FontFile(object):
    def __init__(self, file_data):
        self.image_count = unpack('>H', file_data[0:2])[0]
        self.header_length = self.image_count * 10 + 10
        self.file_length = unpack('>H', file_data[4:6])[0]
        self.file_data = file_data[self.header_length:]
        self.header = file_data[:self.header_length]

        self.headers = [ImageHeader(*xs) for xs in iter_unpack('>4H2B', file_data[10:self.header_length])]




        self.extracted = extract_file(self.file_length, self.file_data)

        self.images = []
        for header in self.headers:
            packed_image_width = header.width // 16 * 2
            num_bit_planes = 4
            image_length = packed_image_width * header.height * num_bit_planes
            image_data = self.extracted[header.data_address:header.data_address+image_length]
            self.images.append(image_data)


    def get_image_height(self, image_number):
        #image_metadata = self.header[image_number * 10 + 0xa: image_number * 10 + 0xa + 10]
        #return unpack('>H', image_metadata[6:8])[0]
        return self.headers[image_number].height

    def get_image_width(self, image_number, bordered=None):
        #image_metadata = self.header[image_number * 10 + 0xa: image_number * 10 + 0xa + 10]
        #image_width = unpack('>H', image_metadata[4:6])[0]
        image_width = self.headers[image_number].width
        # if dx & 8 width:
        test = (((image_width + 0xf) & 0xfff0) >> 4) << 1
        if bordered:
            image_width -= 3
        return image_width

    def test(self, image_number):
        total_images = unpack('>H', self.header[0:2])[0]
        if image_number >= 0 and image_number < total_images:
            metadata_offset = (image_number * 10) + 10

            image_data_location = unpack('>H', self.header[metadata_offset + 2:metadata_offset + 4])[0]
            image_data_location += self.header_length

            image_width = unpack('>H', self.header[metadata_offset + 4:metadata_offset + 6])[0] + 0xf
            packed_image_width = image_width // 16 * 2
            print(image_width, packed_image_width, packed_image_width << 3)

    def extract_subimage(self, piv, image_number, x_offset, y_offset):
        if image_number >= 0 and image_number < self.image_count:

            header = self.headers[image_number]
            blit_type = header.blit_type
            if not blit_type:
                return

            image_data_location = header.data_address + self.header_length

            image_width = header.width + 0xf
            packed_image_width = image_width // 16 * 2
            image_height = header.height

            x_offset_adjust = header.x_adjust >> 4
            x_offset -= x_offset_adjust



            # loc 5e55
            ds_8174 = dx = (y_offset << 4) + (y_offset <<6)

            ax = x_offset & 3
            ds_8163 = ax & 0x00ff
            
            ax = x_offset

            ax = ax >> 2
            bx = ax

            ds_816e = 0
            ds_8172 = 0

            #print(hex(dx))
            ax += dx
            di = ax

            # push ds, si, di
            packed_image_length = packed_image_width * image_height
            si, di, bx, bp, cs_637f =  [ image_data_location + (packed_image_length * i) for i in range(0, 5)]

            cs_637b = 0
            cs_637d = packed_image_length
            #dx = 0x638f + ax

            if blit_type == 1:
                extract = self.recombine_1_bit_image(si, packed_image_length)
                self.pixels = self.recombine(blit_type, [si], packed_image_length)
                assert(self.pixels == extract)
            elif blit_type == 3:
                extract = self.recombine_2_bit_image(si, di, packed_image_length)
                self.pixels = self.recombine(blit_type, [si, di], packed_image_length)
                assert(self.pixels == extract)
            elif blit_type == 7:
                extract = self.recombine_3_bit_image(si, di, bx, packed_image_length)
                self.pixels = self.recombine(blit_type, [si, di, bx], packed_image_length)
                assert(self.pixels == extract)
            elif blit_type == 15:
                extract = self.extract_pixels(si, di, bx, bp, cs_637d)
                self.pixels = self.recombine(blit_type, [si, di, bx, bp], cs_637d)
                assert(self.pixels == extract)
            elif blit_type == 30:
                extract = self.recombine_5_bit_planes_first_zero(
                        si, di, bx, bp, packed_image_length)
                self.pixels = self.recombine(blit_type, [si, di, bx, bp],
                                             packed_image_length)
                assert(self.pixels == extract)
            elif blit_type == 31:
                extract = self.recombine_5_bit_planes(si, di, bx, bp, cs_637f,
                                                        packed_image_length)
                self.pixels = self.recombine(blit_type, [si, di, bx, bp, cs_637f],
                                             packed_image_length)
                assert(self.pixels == extract)
            elif blit_type == 32:
                extract = self.recombine_5_bit_planes_zeroes(si, di, cs_637d)
                #self.pixels = self.recombine(blit_type, [si, di], cs_637d)
                #assert(self.pixels == extract)
            else:
                print('missing blit function {0}'.format(blit_type))

            bx = 0
            bp = image_height
            unpacked_image_width = packed_image_width * 8
            #packed_image_width <<= 3

            image_offset = self.compare_image_width(x_offset=x_offset, image_width=unpacked_image_width)
            if image_offset:
                ds_8172 = image_offset[0]
                unpacked_image_width = image_offset[1]

            cs_638c, cs_638b, cs_5f80, cs_6355, ax = self.sub_5f12(
                    ds_816e,
                    unpacked_image_width,
                    ds_8172,
                    ds_8163
            )

            #self.sub_632a(bp, di, piv, cs_638b, ax)
            self.blit(piv, y_offset, x_offset=x_offset, image_height=image_height, image_width=unpacked_image_width, is_fullscreen=cs_638b)

    def recombine(self, blit_type, bit_plane_positions, length):
        output = [None] * (length * 8)
        o = len(output)

        bit_planes = []
        for position in bit_plane_positions:
            pos = position - self.header_length
            bit_planes.append(self.extracted[pos:pos + length]) 

        sum_func = blit_function_table[blit_type]

        # get the nth byte of every bit_plane
        for i, bytes_list in enumerate(zip(*bit_planes)):
            # get the nth bits of those bytes
            for j, bits in enumerate(zip(*[each_bit_in_byte(byte) for byte in bytes_list])):
                # reconstruct the output byte from those bits
                output[i * 8 + j] = sum_func(bits)

        assert o == len(output)
        return output


    def recombine_1_bit_image(self, bit_plane_position_1, length):
        output = [None] * length * 8
        for i in range(length):
            bit_plane_1 = self.extracted[bit_plane_position_1 - self.header_length + i]
            for j, bit in enumerate(each_bit_in_byte(bit_plane_1)):
                output[i * 8 + j] = bit
        return output

    def recombine_2_bit_image(self, bit_plane_position_1, bit_plane_position_2, length):
        output = [None] * length * 8
        for i in range(length):
            bit_plane_1 = self.extracted[bit_plane_position_1 - self.header_length + i]
            bit_plane_2 = self.extracted[bit_plane_position_2 - self.header_length + i]
            for j, bits in enumerate(zip(each_bit_in_byte(bit_plane_1),
                                        each_bit_in_byte(bit_plane_2))):
                output[i * 8 + j] = sum(bit << n for n, bit in enumerate(bits))
        return output

    def recombine_3_bit_image(self, bit_plane_position_1, bit_plane_position_2,
                              bit_plane_position_3, length):
        output = [None] * length * 8
        for i in range(length):
            bit_plane_1 = self.extracted[bit_plane_position_1 - self.header_length + i]
            bit_plane_2 = self.extracted[bit_plane_position_2 - self.header_length + i]
            bit_plane_3 = self.extracted[bit_plane_position_3 - self.header_length + i]
            for j, bits in enumerate(zip(each_bit_in_byte(bit_plane_1),
                                         each_bit_in_byte(bit_plane_3),
                                         each_bit_in_byte(bit_plane_2))):
                output[i * 8 + j] = sum(bit << n for n, bit in enumerate(bits))
        return output

    def recombine_5_bit_planes_first_zero(self, bit_plane_position_2,
                               bit_plane_position_3, bit_plane_position_4,
                               bit_plane_position_5, length):
        output = [None] * length * 8
        o = len(output)
        for i in range(length):
            bit_plane_1 = 0
            bit_plane_2 = self.extracted[bit_plane_position_2 - self.header_length + i]
            bit_plane_3 = self.extracted[bit_plane_position_3 - self.header_length + i]
            bit_plane_4 = self.extracted[bit_plane_position_4 - self.header_length + i]
            bit_plane_5 = self.extracted[bit_plane_position_5 - self.header_length + i]

            for j, x in enumerate(zip(each_bit_in_byte(bit_plane_1),
                                      each_bit_in_byte(bit_plane_2),
                                      each_bit_in_byte(bit_plane_3),
                                      each_bit_in_byte(bit_plane_4),
                                      each_bit_in_byte(bit_plane_5))):
                output[i * 8 + j] = sum(bit << n for n, bit in enumerate(x))
        #print_hex_view(output)
        assert o == len(output)
        return output

    def recombine_5_bit_planes(self, bit_plane_position_1, bit_plane_position_2,
                               bit_plane_position_3, bit_plane_position_4,
                               bit_plane_position_5, length):
        output = [None] * length * 8
        o = len(output)
        for i in range(length):
            bit_plane_1 = self.extracted[bit_plane_position_1 - self.header_length + i]
            bit_plane_2 = self.extracted[bit_plane_position_2 - self.header_length + i]
            bit_plane_3 = self.extracted[bit_plane_position_3 - self.header_length + i]
            bit_plane_4 = self.extracted[bit_plane_position_4 - self.header_length + i]
            bit_plane_5 = self.extracted[bit_plane_position_5 - self.header_length + i]

            for j, x in enumerate(zip(each_bit_in_byte(bit_plane_1),
                                      each_bit_in_byte(bit_plane_2),
                                      each_bit_in_byte(bit_plane_3),
                                      each_bit_in_byte(bit_plane_4),
                                      each_bit_in_byte(bit_plane_5))):
                output[i * 8 + j] = sum(bit << n for n, bit in enumerate(x))
        #print_hex_view(output)
        assert o == len(output)
        return output

    def recombine_5_bit_planes_zeroes(self, bit_plane_position_1, bit_plane_position_2, length):
        output = [None] * length * 8
        o = len(output)
        for i in range(length):
            bit_plane_1 = self.extracted[bit_plane_position_1 - self.header_length + i]
            bit_plane_2 = self.extracted[bit_plane_position_2 - self.header_length + i]
            bit_plane_3 = 0
            bit_plane_4 = 0
            bit_plane_5 = bit_plane_1 | bit_plane_2
            #bit_plane_5 = self.extracted[bit_plane_position_1 - self.header_length + i] | self.extracted[bit_plane_position_2 - self.header_length + i]

            for j, x in enumerate(zip(each_bit_in_byte(bit_plane_1),
                                      each_bit_in_byte(bit_plane_2),
                                      each_bit_in_byte(bit_plane_3),
                                      each_bit_in_byte(bit_plane_4),
                                      each_bit_in_byte(bit_plane_5))):
                output[i * 8 + j] = sum(bit << n for n, bit in enumerate(x))
        #print_hex_view(output)
        assert o == len(output)
        return output

    def extract_pixels(self, bit_plane_position_1, bit_plane_position_2,
                       bit_plane_position_3, bit_plane_position_4, length):
        output = [None] * length * 8
        o = len(output)
        for i in range(length):
            bit_plane_1 = self.extracted[bit_plane_position_1 - self.header_length + i]
            bit_plane_2 = self.extracted[bit_plane_position_2 - self.header_length + i]
            bit_plane_3 = self.extracted[bit_plane_position_3 - self.header_length + i]
            bit_plane_4 = self.extracted[bit_plane_position_4 - self.header_length + i]

            for j, x in enumerate(zip(each_bit_in_byte(bit_plane_1),
                                      each_bit_in_byte(bit_plane_2),
                                      each_bit_in_byte(bit_plane_3),
                                      each_bit_in_byte(bit_plane_4))):
                output[i * 8 + j] = sum(bit << n for n, bit in enumerate(x))
        #print_hex_view(output)
        assert o == len(output)
        return output

    def sub_7969(self, y_offset):
        if y_offset < 0:
            pass


    def sub_793e(self):
        pass

    def compare_image_width(self, x_offset, image_width):
        total = x_offset + image_width
        if total > SCREEN_WIDTH and x_offset < SCREEN_WIDTH:
            overrun = total - SCREEN_WIDTH
            return overrun, image_width - overrun

    def sub_7907(self, r_offset):
        pass

    def sub_5f12(self, ds_816e, packge_image_width, ds_8172, ds_8163):
        si = ds_816e
        ds_80b9 = 0xa800
        es = ds_80b9 # = a800 graphics address
        dx = 0x50 # 80
        ax = packge_image_width & 0x0003

        cs_638b = ax
        cs_638c = ax
        ax = packge_image_width >> 2
        dx -= ax
        dx = dx << 2
        ax = dx
        dx = dx << 1
        #ax += dx
        dx += ax
        cs_5f80 = dx

        ax = 0x50
        dx = packge_image_width
        dx = dx >> 2
        ax -= dx
        cs_6355 = ax

        ax = ds_8172 + cs_638c
        cs_6359 = ax
        al = ds_8163
        bx = 0x8178 + al
        al = ds_8178[bx]
        #ax = (2 << 8) + al
        ax = (al << 8) + 2

        #print(hex(cs_638c), hex(cs_638b), hex(cs_5f80), hex(cs_6355))
        return cs_638c, cs_638b, cs_5f80, cs_6355, ax

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
                dest += 1
                src += 1
            first_pass = False


        #length = image_height * 320 
        #y_pos = y_offset * 320 + x_offset
        #for src, dest in enumerate(range(y_pos, y_pos + length)):
        #    try:
        #        if self.pixels[src] != 0:
        #            piv.pixels[dest] = self.pixels[src]
        #    except Exception as e:
        #        pass


    def sub_632a(self, bp, di, piv, cs_638b, ax):
        i = 0
        original_i = 0
        original_di = di

        i_s = []

        for bx in range(4):
            for b in range(bp):
                al = self.pixels[i]
                i_s.append(i)
                i += 3 + 1
                if al != 0:
                    piv.pixels[di] = al

                di += 1
                al = self.pixels[i]
                i_s.append(i)
                i += 3 + 1
                if al != 0:
                    piv.pixels[di] = al

                di += 1
                if not cs_638b <= 0:
                    al = self.pixels[i]
                    i_s.append(i)
                    if al != 0:
                        piv.pixels[di] = al

                di += 0x2# 0x130
                i += 0x8# 0x101

            # pop di, si, ax
            di = original_di
            # inc si
            original_i = original_i + 1
            i = original_i
            ah = (0xff00 & ax) >> 8
            ah = ah << 1
            # rol ah, 1
            if (ah & 0x80) >> 7:
                di += 1

            cs_638b -= 1


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
