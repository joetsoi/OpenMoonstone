import os
import struct
from itertools import repeat, zip_longest

import sys
import pygame
from pygame.locals import *


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return zip_longest(fillvalue=fillvalue, *args)


def extract(file_length, pixel_data):
    extracted = bytearray()
    offset = 0
    debug = False

    while(offset != file_length):
    #for i in range(229):
        header_block = struct.unpack_from('>B', pixel_data, offset)[0]
        #print("bx: ", hex(70+offset), end='')
        offset += 1
        #print("\t dx:[bx]: ", hex(header_block))
        #if offset >= 0x31d8 and offset <= 0x31e8:

        # 34de:5893
        #if offset > 0x3115 - (6+64) and offset <= 0x312a - (6+64):
        #if len(extracted) >= 0x18f4:
        #if len(extracted) >= 0x18e4:

        #if offset == 0x1072:
        #    print("\t dx:[bx]: ", hex(header_block), hex(offset)) #+ 6+64 -1))
        #    debug = True

        #if offset >= 0x5700: #and offset <= 0x58a0:
        #    print("\t dx:[bx]: ", hex(header_block), hex(offset))

        for is_encoded in each_bit(header_block):
            if is_encoded:
                encoded = struct.unpack_from('>H',  pixel_data, offset)[0]
                offset += 2
                count = 0x22 - ((encoded & 0xf800) >> 11)
                bottom = encoded & 0x7ff

                copy_from = len(extracted) - bottom

                new_bytes = extracted[copy_from:copy_from+count]
                extra_bytes = copy_from + count - len(extracted)
                #if (copy_from + count) > len(extracted):
                #if extra_bytes > 0:
                for extra in range(extra_bytes):
                    #print("extra:", new_bytes[extra])
                    new_bytes += bytes([new_bytes[extra]])

                    #new_bytes += bytes(repeat(0,  copy_from + count - len(extracted)))
                    #print(blah)
                    #print("extra zeros", blah)
                    #print(copy_from + count - len(extracted))

                #if i == 228:
                #if offset == 0x31e8:
                if debug:
                    print("copy previous", hex(encoded))
                    print("len(extr) ", hex(len(extracted)))
                    print("offset: ", offset, "copy_from: ", hex(copy_from), "count ", hex(count), "bottom ", hex(bottom))
                    #print(extracted[copy_from:copy_from+count])
                    print(new_bytes)
                    print()
                extracted += new_bytes
            else:
                extracted += struct.unpack_from('>c',  pixel_data, offset)[0]
                offset += 1
                #if i == 228:
                #if offset == 0x31e8:
                if debug:
                    print("as is", hex(extracted[-1]))
                    print("len(extr): ", hex(len(extracted)))
                    print()


            if offset >= file_length:
                break
        debug = False

    #for i in range(0, len(extracted), 0x10):
    #    print(hex(i), end=' ')
    #    for j in range(0, 0x10):
    #        if i+j < len(extracted):
    #            print(hex(extracted[i+j]), end=' ')
    #    print()

    #print("length (hex): ", hex(len(extracted)))
    #print("length: ", len(extracted))
    #print("number of bytes processed: ", 70+offset)
    #print("number of bytes processed hex: ", hex(70+offset))
    #print(hex(extracted[0x3d20]))
    return extracted


def each_bit(byte):
    def get_bit(byte, bit_number):
        return (byte & (1 << bit_number)) != 0

    for i in reversed(range(8)):
        yield get_bit(byte, i)


def extract2(pixel_data):
    memory_width = 40 * 200
    planes = [i * memory_width for i in range(5)]
    output = []

    block_a = []
    block_b = []
    block_c = []
    block_d = []

    for i in range(memory_width):
        dh = pixel_data[i]
        dl = pixel_data[planes[1] + i]
        ch = pixel_data[planes[2] + i]
        cl = pixel_data[planes[3] + i]
        ah = pixel_data[planes[4] + i]

        #if i in range(0xc0, 0xcd+4):
        #    print(hex(dh), hex(dl), hex(ch), hex(cl), hex(al))
        line = []
        #for x in zip(each_bit(ah), each_bit(cl), each_bit(ch), each_bit(dl), each_bit(dh)):
        for x in zip(each_bit(dh), each_bit(dl), each_bit(ch), each_bit(cl), each_bit(ah)):
            al = 0
            for n, bit in enumerate(x):
                al += bit << n
            line.append(al)
            #if i in range(0xcd, 0xcd+3):
            #    print(hex(al))

            #for j in range(4):
            #    output[j].append(
        #block_a.append(line[0])
        #block_b.append(line[1])
        #block_c.append(line[2])
        #block_d.append(line[3])

        #block_a.append(line[4])
        #block_b.append(line[5])
        #block_c.append(line[6])
        #block_d.append(line[7])
        output += line

        block_a.append(line[0])
        block_b.append(line[1])
        block_c.append(line[2])
        block_d.append(line[3])

        block_a.append(line[4])
        block_b.append(line[5])
        block_c.append(line[6])
        block_d.append(line[7])

    #return block_a + block_b + block_c + block_d
    return output

def extract_palette(palette_data):
    extracted = []
    for pel in palette_data:
        test = pel & 0x7fff
        #extracted += test.to_bytes(2, byteorder='little')
        extracted.append(test)
    return extracted

def extract_palette_2(palette_data):
    extracted = []
    for pel in palette_data:
        pel_bytes = pel.to_bytes(2, byteorder='little')
        extracted.append( int((pel_bytes[1] << 2) /64 * 256))
        g = (pel_bytes[0] & 0xf0) >> 2
        extracted.append( int(g / 64 * 256))
        b = (pel_bytes[0] & 0x0f) << 2
        extracted.append(int(b / 64 * 256))
    return extracted


def print_hex_view(data):
    for i in range(0, len(data), 0x10):
        print(hex(i), ":", end=' ')
        for j in range(0, 0x10):
            if i+j < len(data):
                print(hex(data[i+j]), end=' ')
        print()

if __name__ == "__main__":
    with open('MINDSCAP', 'rb') as f:
        file_data = f.read()
    #print(type(file_data))

    file_type = struct.unpack('>H', file_data[0:2])
    #print(file_type)

    file_length, = struct.unpack('>H', file_data[4:6])
    #print(file_length)

    palette = struct.unpack('>32H', file_data[6:6+64])
    #print(palette)

    extracted = extract(file_length, file_data[6+64:])
    with open('mindscap_extract_1.bin', 'rb') as f:
        test_data = f.read()

    for i, (found, test) in enumerate(zip(extracted, test_data)):
        if found != test:
            print(hex(i), hex(found), hex(test))
            break
    else:
        print("file and output match")

    with open('mindscap_video_mem.bin', 'rb') as f:
        test_data = f.read()

    #print_hex_view(extracted[0x1810:0x1810+0x10])
    #print_hex_view(extracted[0x5e80:0x5f00])
    extracted = extract2(extracted)
    #print_hex_view(extracted[0x190:0x190+0x10])

    for i, (found, test) in enumerate(zip(extracted, test_data)):
        if found != test:
            print(hex(i), hex(found), hex(test))
            break
    else:
        print("file and output match")
    #print(extracted == bytearray(test_data))
    #print_hex_view(palette)
    #print()
    #print(palette)
    print(len(extracted))

    e_pal = extract_palette(palette)
    pal_2 = extract_palette_2(e_pal)

    print_hex_view(pal_2)
    palette = list(grouper(pal_2, 3))
    print([i for i in grouper(pal_2, 3)])

    pygame.init()
    screen = pygame.display.set_mode((320 * 4, 200 * 4))

    image = pygame.Surface((320, 200))
    image.fill((255, 255, 255))
    pixel_array = pygame.PixelArray(image)
    for x, line in enumerate(grouper(extracted, 320)):
        for y, pixel in enumerate(line):
            #pixel_array[y][x] = (255, 255, 255)#pal_2[pixel]
            pixel_array[y][x] = palette[pixel]
            #print(palette[pixel])
    del pixel_array
    image = pygame.transform.scale(image, (320 * 4, 200 * 4))
    screen.blit(image, (0, 0))
    while True:
        for event in pygame.event.get():
            if event.type == QUIT:
                pygame.quit()
                sys.exit()
            pygame.display.update()
            pygame.time.wait(100)
