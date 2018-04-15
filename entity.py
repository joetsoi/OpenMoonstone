from attr import attrs, attrib

from collide import Collider
from graphics import Graphic
from controller import Controller
from movement import Movement
from logic import Logic
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

