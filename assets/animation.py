from typing import NamedTuple


class ImagePosition(NamedTuple):
    spritesheet: str
    image_number: int
    y: int
    x: int


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
            ImagePosition('kn1.ob', 1, 45, -13),
            ImagePosition('kn1.ob', 0, -9, -9),
            ImagePosition('kn4.ob', 1, -6, 4),
        ),

    ),
    'walk': (
        (
            ImagePosition('kn1.ob', 3, 46, -13),
            ImagePosition('kn1.ob', 2, -9, -9),
            ImagePosition('kn4.ob', 1, -6, 3),
        ),
        (
            ImagePosition('kn1.ob', 5, 35, -13),
            ImagePosition('kn1.ob', 4, -9, -3),
            ImagePosition('kn4.ob', 1, -6, 6),
        ),
        (
            ImagePosition('kn1.ob', 7, 24, -13),
            ImagePosition('kn1.ob', 6, -8, -9),
            ImagePosition('kn4.ob', 1, -6, 1),
        ),
        (
            ImagePosition('kn1.ob', 9, 27, -13),
            ImagePosition('kn1.ob', 8, -9, -4),
            ImagePosition('kn4.ob', 1, -9, 12),
        ),
    ),

    'up': (
        (
            ImagePosition('kn4.ob', 0, -19, 2),
            ImagePosition('kn1.ob', 10, -8, -10),
        ),
        (
            ImagePosition('kn4.ob', 0, -20, 3),
            ImagePosition('kn1.ob', 11, -10, -9),
        ),
        (
            ImagePosition('kn4.ob', 0, -18, 3),
            ImagePosition('kn1.ob', 12, -8, -9),
        ),
        (
            ImagePosition('kn4.ob', 0, -18, 2),
            ImagePosition('kn1.ob', 13, -8, -9),
        ),
    ),
    'down': (
        (
            ImagePosition('kn1.ob', 14, -8, -12),
            ImagePosition('kn4.ob', 0, -14, -5),
        ),
        (
            ImagePosition('kn1.ob', 15, -7, -10),
            ImagePosition('kn4.ob', 0, -14, -2),
        ),
        (
            ImagePosition('kn1.ob', 16, -8, -13),
            ImagePosition('kn4.ob', 0, -15, -5),
        ),
        (
            ImagePosition('kn1.ob', 17, -8, -12),
            ImagePosition('kn4.ob', 0, -17, -6),
        ),
    ),
}