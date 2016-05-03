import pdb
from pprint import pprint


from collections import namedtuple
import os, sys
from struct import unpack
from extract import extract_file
from cli import print_hex_view
from piv import each_bit_in_byte, PivFile

# 4ce4:5ba7
ds_8178 = {
    0x8178: 0x11,
    0x8179: 0x22,
    0x817a: 0x44,
    0x817b: 0x88,
}

ImageDimension = namedtuple('ImageDimension', 'width, height, x_offset, y_offset')


def draw_string(piv, font, text, y, main_exe):
    image_numbers = []
    image_widths = []
    ords = []
    for char in text:
        image_number = main_exe.bold_f_char_lookup[ord(char) - 0x20]
        ords.append(ord(char))
        image_numbers.append(image_number)
        meta = main_exe.strings[text]
        image_widths.append(font.get_image_width(image_number))

    screen_dimensions = main_exe.screen_dimensions
    image_width = sum(image_widths)
    center = int(((screen_dimensions.right - screen_dimensions.left) - image_width) / 2)

    for i, w in zip(image_numbers, image_widths):
        font.extract_subimage(piv, i, center, y)
        center += w


class FontFile(object):
    def __init__(self, file_data):
        self.header_length = unpack('>H', file_data[0:2])[0] * 10 + 10
        self.file_length = unpack('>H', file_data[4:6])[0]
        self.file_data = file_data[self.header_length:]
        self.header = file_data[:self.header_length]

        self.extracted = extract_file(self.file_length, self.file_data)
        #print("length", len(self.extracted))

    def get_image_width(self, image_number):
        image_metadata = self.header[image_number * 10 + 0xa: image_number * 10 + 0xa + 10]
        image_width = unpack('>H', image_metadata[4:6])[0]
        # if dx & 8 width:
        test = (((image_width + 0xf) & 0xfff0) >> 4) << 1
        print(bin(image_width), bin(test))
        image_width -= 3
        return image_width

    def extract_subimage(self, piv, image_number, x_offset, y_offset):
        total_images = unpack('>H', self.header[0:2])[0]
        if image_number >= 0 and image_number < total_images:

            si = (image_number * 10) + 10

            dx = unpack('>H', self.header[si + 2:si + 4])[0]
            dx += self.header_length

            ds_8164 = unpack('>H', self.header[si + 4:si + 6])[0] + 0xf
            ds_8164 = ((ds_8164 & 0x0ff0) >> 4) << 1 # 320 image width? takes off 5?
            #print("ds_8164 : ", hex(ds_8164))

            ds_8168 = unpack('>H', self.header[si + 6:si + 8])[0] # image height
            #print("ds_8168 : ", hex(ds_8168))

            ax = self.header[si + 8] >> 4
            x_offset -= ax

            cs_638e = self.header[si + 9]

            if not cs_638e:
                return

            # loc 5e55
            si = dx
            ds_816c = y_offset # image y offset
            ds_8174 = dx = (y_offset << 4) + (y_offset <<6)

            ax = x_offset & 3
            ds_8163 = ax & 0x00ff
            


            ax = x_offset
            ds_816a = x_offset # 5? related to image width

            ax = ax >> 2
            bx = ax
            

            ds_816e = 0
            ds_8172 = 0

            #print(hex(dx))
            ax += dx
            di = ax
            destination_index = di

            # push ds, si, di

            bx = (bx & 0xff00) + (ds_8168 & 0x00ff)
            ax = (ax & 0xff00) + (ds_8164 & 0x00ff)
            ax = (ax & 0x00ff) * (bx & 0x00ff)

            dx = si + ax
            di = dx
            dx += ax
            bx = dx
            dx += ax
            bp = dx
            dx += ax
            cs_637f = dx

            cs_637b = 0
            cs_637d = ax
            ax = ax & 0x00ff
            ax = cs_638e << 1
            dx = 0x638f + ax
            dx, bx = bx, dx

            #self.pixels = self.extract_pixels(bx-si, dx-si, si-si, di-si, bp-si, cs_637d)
            self.pixels = self.extract_pixels(bx, dx, si, di, bp, cs_637d)

            bx = 0
            bp = ds_8168
            ax = ds_8164 << 3
            ds_8164 = ax #image height

            image_offset = self.sub_78e1(ds_816a, ds_8164)
            if image_offset:
                ds_8172 = image_offset[0]
                ds_8164 = image_offset[1]
            # ds_8172 is x-offset
            # ds_8172 image width

            cs_638c, cs_638b, cs_5f80, cs_6355, ax = self.sub_5f12(
                    ds_816e,
                    ds_8164,
                    ds_8172,
                    ds_8163
            )
            
            #print(hex(cs_638c), hex(cs_638b), hex(cs_5f80), hex(cs_6355), hex(ax))

            #print(bp, di, piv, cs_638b, ax)
            #self.sub_632a(bp, di, piv, cs_638b, ax)
            
            # image x and y offset, image height/source address
            self.blit(piv, y_offset, ds_816a, ds_8168, ds_8164, cs_638b)
            #self.blit(piv, source_address, ds_816c)


            #print(hex(ax), hex(bx), hex(cx), hex(dx), hex(si))

    def extract_pixels(self, bx, dx, si, di, bp, length):
        dx, bx = bx, dx
        output = []
        for i in range(length):
            dh = self.extracted[si - self.header_length + i]
            dl = self.extracted[di - self.header_length + i]
            ch = self.extracted[bx - self.header_length + i]
            cl = self.extracted[bp - self.header_length + i]

            for x in zip(each_bit_in_byte(dh), each_bit_in_byte(dl),
                         each_bit_in_byte(ch), each_bit_in_byte(cl)):
                al = sum(bit << n for n, bit in enumerate(x))
                output.append(al)
        #print_hex_view(output)
        return output

    def sub_7969(self, ds_816c):
        if ds_816c < 0:
            pass


    def sub_793e(self):
        pass

    def sub_78e1(self, ds_816a, ds_8164):
        # compare image width
        ax = ds_816a + ds_8164
        if ax > 0x140 and ds_816a < 0x140:
            ax -= 0x140
            ds_8172 = ax
            return ds_8172, ds_8164 - ax

    def sub_7907(self, ds_816a):
        pass

    def sub_5f12(self, ds_816e, ds_8164, ds_8172, ds_8163):
        si = ds_816e
        ds_80b9 = 0xa800
        es = ds_80b9 # = a800 graphics address
        dx = 0x50 # 80
        ax = ds_8164 & 0x0003

        cs_638b = ax
        cs_638c = ax
        ax = ds_8164 >> 2
        dx -= ax
        dx = dx << 2
        ax = dx
        dx = dx << 1
        #ax += dx
        dx += ax
        cs_5f80 = dx

        ax = 0x50
        dx = ds_8164
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

    for i in range(76):
        font.get_image_width(i)
