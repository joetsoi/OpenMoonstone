from collections import namedtuple
from struct import unpack

import sark


ImagePosition = namedtuple('ImagePosition', 'spritesheet image_number y collide x')


def hex_to_sign(value):
    if value >= 0x8000:
        value -= 0x10000
    return value


def byte_to_sign(value):
    if value >= 0x80:
        value -= 0x100
    return value


KNIGHT = 'AnimationFrame'
TROGG_SPEAR = 'TroggSpearImage'
BALOK = 'BalokImage'

spritesheets = {
    KNIGHT: {
        0: 'kn1.ob',
        4: 'kn2.ob',
        8: 'kn3.ob',
        12: 'kn4.ob',
        16: 'kn4.ob',
    },
    TROGG_SPEAR: {
        0: 'troggsp1.cel',
        4: 'troggsp2.cel',
    },
    BALOK: {
        0: 'balok1.cel',
        4: 'balok2.cel',
        8: 'balok3.cel',
    },
}

collide_type = {
    0: 'NonSolid',
    1: 'Collidee',
    2: 'Collider',
    16: 'Vm',
    32: 'WeaponHand',
    64: 'UpdateEdge',
    65: 'Collidee',
    66: 'Collider',
    128: 'Blood',
    144: 'BloodStain',
}

animations = [
    KNIGHT,
    TROGG_SPEAR,
    BALOK,
]

line = sark.Line()
next_line = True


while next_line:
    image_type = line.disasm.split()[0]
    if image_type in animations:
        sprite, img_num, y, collide, x = unpack('<4BH', line.bytes)
        y = byte_to_sign(y)
        x = hex_to_sign(x)
        sprite = spritesheets[image_type][sprite]
        collide = collide_type[collide]

        #test = "ImagePosition('{}', {}, {}, {}, {}),".format(sprite, img_num, y, x, collide)
        test = '  (sheet: "{}", image: {}, y: {}, x: {}, image_type:{}),'.format(sprite, img_num, y, x, collide)
        print test
        line = line.next
    elif line.disasm.startswith('EndOfAnimFrame <0FFh, 0>'):
        line = line.next

        # print '),'
        print '],'
        print 'images: ['
    elif line.disasm.startswith('EndOfAnimFrame <0FFh, 0FFh>'):
        next_line = False
    else:
        line = line.next
