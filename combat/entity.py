from attr import attrib, attrs

from .system import SystemFlag


@attrs(auto_attribs=True, slots=True)
class Entity:
    controller: 'Controller' = attrib(default=None)
    movement: 'Movement' = attrib(default=None)
    graphics: 'Graphics' = attrib(default=None)
    collision: 'Collision' = attrib(default=None)
    logic: 'Logic' = attrib(default=None)
    state: 'AnimationState' = attrib(default=None)
    blood: 'Blood' = attrib(default=None)
    audio: 'Audio' = attrib(default=None)

    @property
    def flags(self):
        flags = 0
        for slot in self.__slots__:
            component = getattr(self, slot)
            if component is not None:
                component_type = type(component).__name__.upper()
                flags += getattr(SystemFlag, component_type)
        return SystemFlag(flags)


