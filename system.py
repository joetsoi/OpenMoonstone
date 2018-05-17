from enum import IntFlag


class SystemFlag(IntFlag):
    controller = 1
    movement = 2
    graphics = 4
    collision = 8
    logic = 16
    state = 32
    blood = 64
    audio = 128
