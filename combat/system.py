from enum import IntFlag


class SystemFlag(IntFlag):
    CONTROLLER = 1
    MOVEMENT = 2
    GRAPHICS = 4
    COLLISION = 8
    LOGIC = 16
    ANIMATIONSTATE = 32
    BLOODSTAIN = 64
    AUDIO = 128
    AICONTROLLER = 256
