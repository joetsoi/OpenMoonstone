from enum import IntFlag


class SystemFlag(IntFlag):
    controller = 1
    movement = 2
    graphics = 4
    collider = 8
    logic = 16
