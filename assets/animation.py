from enum import IntFlag
from typing import NamedTuple


class Collide(IntFlag):
    NON_SOLID = 0
    COLLIDEE = 1
    COLLIDER = 2


class ImagePosition(NamedTuple):
    spritesheet: str
    image_number: int
    y: int
    x: int
    collide: Collide


def hex_to_sign(value):
    if value >= 0x8000:
        value -= 0x10000
    return value

def byte_to_sign(value):
    if value >= 0x80:
        value -= 0x100
    return value


knight = {
    'idle': (
        (
            ImagePosition('kn1.ob', 1, 45, -13, Collide.NON_SOLID),
            ImagePosition('kn1.ob', 0, -9, -9, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 1, -6, 4, Collide.NON_SOLID),
        ),

    ),
    'walk': (
       (
           ImagePosition('kn1.ob', 3, 46, -13, Collide.NON_SOLID),
           ImagePosition('kn1.ob', 2, -9, -9, Collide.COLLIDEE),
           ImagePosition('kn4.ob', 1, -6, 3, Collide.NON_SOLID),
       ),
       (
           ImagePosition('kn1.ob', 5, 35, -13, Collide.COLLIDEE),
           ImagePosition('kn1.ob', 4, -9, -3, Collide.COLLIDEE),
           ImagePosition('kn4.ob', 1, -6, 6, Collide.NON_SOLID),
       ),
       (
           ImagePosition('kn1.ob', 7, 24, -13, Collide.COLLIDEE),
           ImagePosition('kn1.ob', 6, -8, -9, Collide.COLLIDEE),
           ImagePosition('kn4.ob', 1, -6, 1, Collide.NON_SOLID),
       ),
       (
           ImagePosition('kn1.ob', 9, 27, -13, Collide.COLLIDEE),
           ImagePosition('kn1.ob', 8, -9, -4, Collide.COLLIDEE),
           ImagePosition('kn4.ob', 1, -9, 12, Collide.NON_SOLID),
       ),
    ),
    'up': (
        (
            ImagePosition('kn4.ob', 0, -19, 2, Collide.NON_SOLID),
            ImagePosition('kn1.ob', 10, -8, -10, Collide.COLLIDEE),
        ),
        (
            ImagePosition('kn4.ob', 0, -20, 3, Collide.NON_SOLID),
            ImagePosition('kn1.ob', 11, -10, -9, Collide.COLLIDEE),
        ),
        (
            ImagePosition('kn4.ob', 0, -18, 3, Collide.NON_SOLID),
            ImagePosition('kn1.ob', 12, -8, -9, Collide.COLLIDEE),
        ),
        (
            ImagePosition('kn4.ob', 0, -18, 2, Collide.NON_SOLID),
            ImagePosition('kn1.ob', 13, -8, -9, Collide.COLLIDEE),
        ),
    ),
    'down': (
        (
            ImagePosition('kn1.ob', 14, -8, -12, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -14, -5, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn1.ob', 15, -7, -10, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -14, -2, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn1.ob', 16, -8, -13, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -15, -5, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn1.ob', 17, -8, -12, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -17, -6, Collide.NON_SOLID),
        ),
    ),
    'swing': (
        (
            ImagePosition('kn1.ob', 32, 44, -22, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 31, -4, -18, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 3, 25, -22, Collide.COLLIDER),
        ),
        (
            ImagePosition('kn1.ob', 32, 44, -22, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 31, -4, -18, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 3, 25, -22, Collide.COLLIDER),
        ),
        (
            ImagePosition('kn1.ob', 34, -3, 4, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 33, 24, -14, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 4, 21, 15, Collide.COLLIDER),
            ImagePosition('kn4.ob', 14, 34, 10, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn1.ob', 35, 27, -14, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 36, 7, 17, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 37, 22, 35, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 38, 45, 33, Collide.NON_SOLID),
            ImagePosition('kn4.ob', 5, 23, 60, Collide.COLLIDER),
            ImagePosition('kn4.ob', 15, 25, 41, Collide.COLLIDER),
        ),
        (
            ImagePosition('kn1.ob', 39, 20, -12, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 1, -7, 18, Collide.COLLIDER),
            ImagePosition('kn1.ob', 40, 2, 15, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 16, -6, 34, Collide.COLLIDER),
            ImagePosition('kn4.ob', 17, 3, 61, Collide.COLLIDER),
        ),
        (
            ImagePosition('kn1.ob', 41, -1, -13, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 42, 21, 15, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 18, -21, -23, Collide.COLLIDER),
            ImagePosition('kn4.ob', 6, -22, -25, Collide.COLLIDER),
        ),
        (
            ImagePosition('kn1.ob', 41, -1, -13, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 42, 21, 15, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 6, -22, -25, Collide.COLLIDER),
        ),
        (
            ImagePosition('kn1.ob', 19, 44, -21, Collide.COLLIDEE),
            ImagePosition('kn1.ob', 18, -7, -14, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 1, -15, 12, Collide.COLLIDER),
        ),
    ),
    'some': (
        (
            ImagePosition('kn3.ob', 10, -2, -26, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 9, -12, -16, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 11, 13, -26, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -25, 5, Collide.COLLIDEE),
        ),
        (
            ImagePosition('kn3.ob', 12, 0, -38, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 13, 21, -27, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 14, 24, -3, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -15, -1, Collide.COLLIDEE),
        ),
        (
            ImagePosition('kn3.ob', 12, 0, -38, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 15, 22, -24, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 16, 39, 19, Collide.COLLIDEE),
            ImagePosition('kn3.ob', 17, 49, 17, Collide.COLLIDEE),
            ImagePosition('kn4.ob', 0, -15, -1, Collide.COLLIDEE),
        ),
    ),
    'damage_2': (
        (
            ImagePosition('kn3.ob', 0, -8, -25, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 1, 3, -33, Collide.NON_SOLID),
            ImagePosition('kn4.ob', 0, -14, 2, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn3.ob', 3, 46, -25, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 2, 5, -15, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 4, 2, -35, Collide.NON_SOLID),
            ImagePosition('kn4.ob', 1, -2, -7, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn3.ob', 3, 46, -25, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 2, 5, -15, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 5, 19, -45, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 6, 0, -15, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 17, 49, -61, Collide.NON_SOLID),
            ImagePosition('kn4.ob', 1, -2, -7, Collide.NON_SOLID),
        ),
        (
            ImagePosition('kn3.ob', 3, 46, -25, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 2, 5, -15, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 7, 4, -23, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 8, -2, -15, Collide.NON_SOLID),
            ImagePosition('kn3.ob', 17, 49, -61, Collide.NON_SOLID),
            ImagePosition('kn4.ob', 1, -2, -7, Collide.NON_SOLID),
        ),
    ),
    'death': (
         (
             ImagePosition('kn3.ob', 23, 40, -59, Collide.NON_SOLID),
             ImagePosition('kn3.ob', 22, 21, -28, Collide.NON_SOLID),
             ImagePosition('kn3.ob', 28, -19, -25, Collide.NON_SOLID),
         ),
    )
}
