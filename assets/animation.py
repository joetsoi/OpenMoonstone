from enum import IntFlag
from typing import NamedTuple, Optional, Tuple

from attr import attrib, attrs


class FrameType(IntFlag):
    NON_SOLID = 0
    COLLIDEE = 1
    COLLIDER = 2
    BLOOD = 128
    BLOOD_STAIN = 144


class ImagePosition(NamedTuple):
    spritesheet: str
    image_number: int
    y: int
    x: int
    collide: FrameType


@attrs(slots=True, auto_attribs=True)
class AnimationDefinition:
    frames: Tuple[Tuple[ImagePosition]]
    order: Optional[Tuple[int]] = None

    def __iter__(self):
        order = self.order
        if not self.order:
            order = range(len(self.frames))

        for i in order:
            yield self.frames[i]

    def __getitem__(self, i):
        if self.order:
            return self.frames[self.order[i]]
        else:
            return self.frames[i]


def hex_to_sign(value):
    if value >= 0x8000:
        value -= 0x10000
    return value


def byte_to_sign(value):
    if value >= 0x80:
        value -= 0x100
    return value


knight = {
    'idle': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn1.ob', 1, 45, -13, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 0, -9, -9, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -6, 4, FrameType.NON_SOLID),
            ),
        ),
    ),
    'walk': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn1.ob', 3, 46, -13, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 2, -9, -9, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -6, 3, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 5, 35, -13, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 4, -9, -3, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -6, 6, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 7, 24, -13, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 6, -8, -9, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -6, 1, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 9, 27, -13, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 8, -9, -4, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -9, 12, FrameType.NON_SOLID),
            ),
        ),
    ),
    'up': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn4.ob', 0, -19, 2, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 10, -8, -10, FrameType.COLLIDEE),
            ),
            (
                ImagePosition('kn4.ob', 0, -20, 3, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 11, -10, -9, FrameType.COLLIDEE),
            ),
            (
                ImagePosition('kn4.ob', 0, -18, 3, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 12, -8, -9, FrameType.COLLIDEE),
            ),
            (
                ImagePosition('kn4.ob', 0, -18, 2, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 13, -8, -9, FrameType.COLLIDEE),
            ),
        ),
    ),
    'down': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn1.ob', 14, -8, -12, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 0, -14, -5, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 15, -7, -10, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 0, -14, -2, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 16, -8, -13, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 0, -15, -5, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 17, -8, -12, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 0, -17, -6, FrameType.NON_SOLID),
            ),
        ),
    ),
    'swing': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn1.ob', 32, 44, -22, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 31, -4, -18, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 3, 25, -22, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 34, -3, 4, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 33, 24, -14, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 4, 21, 15, FrameType.COLLIDER),
                ImagePosition('kn4.ob', 14, 34, 10, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 35, 27, -14, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 36, 7, 17, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 37, 22, 35, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 38, 45, 33, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 5, 23, 60, FrameType.COLLIDER),
                ImagePosition('kn4.ob', 15, 25, 41, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 39, 20, -12, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -7, 18, FrameType.COLLIDER),
                ImagePosition('kn1.ob', 40, 2, 15, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 16, -6, 34, FrameType.COLLIDER),
                ImagePosition('kn4.ob', 17, 3, 61, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 41, -1, -13, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 42, 21, 15, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 18, -21, -23, FrameType.COLLIDER),
                ImagePosition('kn4.ob', 6, -22, -25, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 41, -1, -13, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 42, 21, 15, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 6, -22, -25, FrameType.COLLIDER),
            ),
            # set next frame AnimationBegin
            (
                ImagePosition('kn1.ob', 1, 45, -13, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 0, -9, -9, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -6, 4, FrameType.COLLIDEE),
            ),
        ),
        order=(0, 0, 1, 2, 3, 4, 5, 6)
    ),
    'thrust': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn1.ob', 53, -7, -18, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 5, 26, -7, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 35, 27, -14, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 36, 7, 17, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 37, 22, 35, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 38, 45, 33, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 5, 23, 60, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 54, 25, -12, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 55, 10, 26, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 56, 25, 50, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 38, 46, 40, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 5, 26, 66, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 54, 25, -12, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 57, 10, 26, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 58, 25, 58, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 38, 46, 40, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 5, 27, 66, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 54, 25, -12, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 59, 18, 26, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 56, 26, 49, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 38, 46, 40, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 5, 27, 65, FrameType.COLLIDER),
            ),
            (
                ImagePosition('kn1.ob', 53, -7, -18, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 5, 26, -7, FrameType.COLLIDER),
            ),
        ),
        order=(0, 0, 0, 0, 1, 2, 3, 4, 5, 5, 5),
    ),
    'some': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn3.ob', 10, -2, -26, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 9, -12, -16, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 11, 13, -26, FrameType.BLOOD),
                ImagePosition('kn4.ob', 0, -25, 5, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn3.ob', 12, 0, -38, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 13, 21, -27, FrameType.BLOOD),
                ImagePosition('kn3.ob', 14, 24, -3, FrameType.BLOOD),
                ImagePosition('kn4.ob', 0, -15, -1, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn3.ob', 12, 0, -38, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 15, 22, -24, FrameType.BLOOD),
                ImagePosition('kn3.ob', 16, 39, 19, FrameType.BLOOD),
                ImagePosition('kn3.ob', 17, 49, 17, FrameType.BLOOD_STAIN),
                ImagePosition('kn4.ob', 0, -15, -1, FrameType.COLLIDEE),
            ),
            (
                ImagePosition('kn3.ob', 18, 8, -37, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 19, 22, -18, FrameType.BLOOD),
                ImagePosition('kn3.ob', 17, 49, 17, FrameType.BLOOD_STAIN),
                ImagePosition('kn4.ob', 6, -5, -15, FrameType.NON_SOLID),
            ),
        ),
        order=(0, 1, 1, 2, 2, 3),
    ),
    'damage_2': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn3.ob', 0, -8, -25, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 1, 3, -33, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 0, -14, 2, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn3.ob', 3, 46, -25, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 2, 5, -15, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 4, 2, -35, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 1, -2, -7, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn3.ob', 3, 46, -25, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 2, 5, -15, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 5, 19, -45, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 6, 0, -15, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 17, 49, -61, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 1, -2, -7, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn3.ob', 3, 46, -25, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 2, 5, -15, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 7, 4, -23, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 8, -2, -15, FrameType.NON_SOLID),
                ImagePosition('kn3.ob', 17, 49, -61, FrameType.NON_SOLID),
                ImagePosition('kn4.ob', 1, -2, -7, FrameType.NON_SOLID),
            ),
        ),
        order=(0, 1, 1, 2, 2, 3),
    ),
    'death': AnimationDefinition(
        frames=(
             (
                 ImagePosition('kn3.ob', 23, 40, -59, FrameType.NON_SOLID),
                 ImagePosition('kn3.ob', 22, 21, -28, FrameType.NON_SOLID),
                 ImagePosition('kn3.ob', 28, -19, -25, FrameType.NON_SOLID),
             ),
        ),
    ),
    'recovery': AnimationDefinition(
        frames=(
            (
                ImagePosition('kn1.ob', 19, 44, -21, FrameType.COLLIDEE),
                ImagePosition('kn1.ob', 18, -7, -14, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -15, 12, FrameType.NON_SOLID),
            ),
            (
                ImagePosition('kn1.ob', 1, 45, -13, FrameType.NON_SOLID),
                ImagePosition('kn1.ob', 0, -9, -9, FrameType.COLLIDEE),
                ImagePosition('kn4.ob', 1, -6, 4, FrameType.NON_SOLID),
            ),
        ),
        order=(0, 1, 1),
    ),
     'end_attack': AnimationDefinition(
         frames=(
             (
                 ImagePosition('kn1.ob', 1, 45, -13, FrameType.COLLIDEE),
                 ImagePosition('kn1.ob', 0, -9, -9, FrameType.COLLIDEE),
                 ImagePosition('kn4.ob', 1, -6, 4, FrameType.COLLIDEE),
             ),
         ),
     ),
}
