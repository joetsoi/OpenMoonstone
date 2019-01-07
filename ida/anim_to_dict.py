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


spritesheets = {
    0: 'kn1.ob',
    4: 'kn2.ob',
    8: 'kn3.ob',
    12: 'kn4.ob',
    16: 'kn4.ob',
}

collide_type = {
    0: 'NonSolid',
    1: 'Collidee',
    2: 'Collider',
    16: 'Vm',
    128: 'Blood',
    144: 'BloodStain',
}


line = sark.Line()
next_line = True
while next_line:
    if line.disasm.startswith("AnimationFrame"):

        sprite, img_num, y, collide, x = unpack('<4BH', line.bytes)
        y = byte_to_sign(y)
        x = hex_to_sign(x)
        sprite = spritesheets[sprite]
        collide = collide_type[collide]

        #test = "ImagePosition('{}', {}, {}, {}, {}),".format(sprite, img_num, y, x, collide)
        test = "  - {{sheet: {}, image: {}, y: {}, x: {}, image_type:{}}}".format(sprite, img_num, y, x, collide)
        print test
        line = line.next
    elif line.disasm.startswith('EndOfAnimFrame <0FFh, 0>'):
        line = line.next

        # print '),'
        print '- images:'
    elif line.disasm.startswith('EndOfAnimFrame <0FFh, 0FFh>'):
        next_line = False
    else:
        line = line.next
