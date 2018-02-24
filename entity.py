from attr import attrs, attrib

from graphics import Graphic
from input import Input
from movement import Movement


@attrs
class Entity:
    input = attrib(type=Input)
    movement = attrib(type=Movement)
    graphics = attrib(type=Graphic)
