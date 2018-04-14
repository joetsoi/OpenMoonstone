from attr import attrs, attrib

from collide import Collider
from graphics import Graphic
from controller import Controller
from movement import Movement
from logic import Logic


@attrs(slots=True)
class Entity:
    controller = attrib(type=Controller)
    movement = attrib(type=Movement)
    graphics = attrib(type=Graphic)
    collider = attrib(type=Collider)
    logic = attrib(type=Logic)
