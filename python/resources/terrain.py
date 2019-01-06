import os
import sys
from collections import namedtuple
from struct import iter_unpack, unpack, unpack_from

import pygame

from cli import print_hex_view
from .extract import extract_file

CmpSubImage = namedtuple('CmpSubImage', ['cmp_file', 'image_number', 'x', 'y'])


class TerrainFile:
    def __init__(self, file_data):
        self.file_length = unpack('>I', file_data[:4])[0]
        self.extracted = extract_file(self.file_length, file_data[4:])

        smallest_t_value = 30

        num_images_to_extract = test = unpack('>H', self.extracted[:2])[0] * 8
        si = 2 + test
        extracted = self.extracted[si:si+2400]
        #extracted = self.extracted[si:si+2400]
        # iter= iter_unpack('>BBHH', self.extracted[si+10:])
        #test = [CmpSubImage._make(i) for i in iter]
        print(self.extracted[si+2400:])

        #print_hex_view(extracted)
        di = 2


        al = unpack('>H', self.extracted[6:8])[0]
        #print(hex(al))
        if al > smallest_t_value:
            smallest_t_value = al

        di += 8
        # unpack extracted to 3H tuples todo
        # first element is cmp file to load
        # 0 = f01.cmp
        # 1 = f01.cmp
        # 2 = sw1.cmp
        # 3 = wa1.cmp
        # 4 = fo2.cmp (default)  if not 0xff, 0xfe or 0-3
        print('test',  len(self.extracted) % 6)

        left = unpack('>H', self.extracted[2:4])[0]
        right = unpack('>H', self.extracted[4:6])[0]
        bottom = unpack('>H', self.extracted[6:8])[0]
        unused_top = unpack('>H', self.extracted[8:10])[0]

        self.boundary = pygame.Rect((left, 30), (right - left, bottom - 30))
        print(self.boundary, self.boundary.bottomright)


        self.positions = []
        images_remaining = True
        while True:
            #print(hex(di))
            subimage_meta = CmpSubImage._make(unpack_from('>BBHH', self.extracted, di))
            if subimage_meta.cmp_file == 0xff:
                break
            #print(subimage_meta)
            self.positions.append(subimage_meta)
            di +=6

        ax, bx, dx = [i for i in sub_7e77(0x4e, 0x51, 0x14)]
        #print(0x4e, 0x51, 0x14 )
        #print_hex_view((ax, bx, dx))
        #print_hex_view(sub_7e8c(ax, bx, dx))
        #print(sub_7e8c(ax, bx, dx))

        for i in range(21):
            ax, bx, dx = [i for i in sub_7e77(0x4e, 0x51, i)]
            #print_hex_view((ax, bx, dx))
            #print_hex_view(sub_7e8c(ax, bx, dx))
            #print(i, sub_7e8c(ax, bx, dx))

def sub_7e77(ax, bx, dx):
    bx = dx // 10 * 25
    ax = -(((dx // 10) * 10) - dx)
    ax = 32 * (dx % 10)
    return ax, bx, dx

def sub_7e8c(ax, bx, dx):
    dx = bx
    bx = 20 * bx
    ax = (ax // 16 + bx) * 2
    return ax, bx, dx
