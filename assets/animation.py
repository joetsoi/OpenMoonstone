from typing import NamedTuple


class FrameImage(NamedTuple):
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
    'walk': (
        (
            FrameImage('kn1.ob', 3, 46, -13),
            FrameImage('kn1.ob', 2, -9, -9),
            FrameImage('kn4.ob', 1, -6, 3),
        ),
        (
            FrameImage('kn1.ob', 5, 35, -13),
            FrameImage('kn1.ob', 4, -9, -3),
            FrameImage('kn4.ob', 1, -6, 6),
        ),
        (
            FrameImage('kn1.ob', 7, 24, -13),
            FrameImage('kn1.ob', 6, -8, -9),
            FrameImage('kn4.ob', 1, -6, 1),
        ),
        (
            FrameImage('kn1.ob', 9, 27, -13),
            FrameImage('kn1.ob', 8, -9, -4),
            FrameImage('kn4.ob', 1, -9, 12),
        ),
    ),
}