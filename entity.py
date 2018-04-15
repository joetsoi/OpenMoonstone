from attr import attrib, attrs

from collide import Collider
from controller import Controller
from graphics import Graphic
from logic import Logic
from movement import Movement
from system import SystemFlag


@attrs(slots=True)
class Entity:
    controller = attrib(type=Controller, default=None)
    movement = attrib(type=Movement, default=None)
    graphics = attrib(type=Graphic, default=None)
    collider = attrib(type=Collider, default=None)
    logic = attrib(type=Logic, default=None)

    @property
    def flags(self):
        flags = 0
        for slot in self.__slots__:
            flags += hasattr(self, slot) * getattr(SystemFlag, slot)
        return SystemFlag(flags)
