from attr import attrib, attrs

from system import SystemFlag


@attrs(auto_attribs=True, slots=True)
class Entity:
    controller: 'Controller' = attrib(default=None)
    movement: 'Movement' = attrib(default=None)
    graphics: 'Graphic' = attrib(default=None)
    collision: 'Collision' = attrib(default=None)
    logic: 'Logic' = attrib(default=None)
    state: 'State' = attrib(default=None)
    blood: 'Blood' = attrib(default=None)
    audio: 'Audio' = attrib(default=None)

    @property
    def flags(self):
        flags = 0
        for slot in self.__slots__:
            has_component = getattr(self, slot) is not None
            flags += int(has_component) * getattr(SystemFlag, slot)
        return SystemFlag(flags)
