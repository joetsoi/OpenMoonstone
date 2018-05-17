from collections import UserList
from enum import Enum, auto

from attr import attrib, attrs

from system import SystemFlag


class State(Enum):
    walking = auto()
    start_attacking = auto()
    attacking = auto()
    busy = auto()
    loop_once = auto()
    destroy = auto()


@attrs(slots=True)
class AnimationState:
    frame_num = attrib(type=int, default=None)
    animation_name = attrib(type=str, default=None)
    animation_len = attrib(type=int, default=None)
    value = attrib(type=State, default=State.walking)


class AnimationStateSystem(UserList):
    flags = SystemFlag.controller + SystemFlag.state

    def update(self):
        for entity in self.data:
            controller = entity.controller
            state = entity.state

            if state.value in [State.attacking, State.busy, State.loop_once]:
                state.frame_num += 1
                if state.frame_num < state.animation_len:
                    continue
                else:
                    if state.value == State.loop_once:
                        state.value = State.destroy
                        state.frame_num = state.animation_len - 1
                    else:
                        state.frame_num = 0
                        state.animation_len = 1
                        state.animation_name = 'idle'
                        state.value = State.walking

            if controller and controller.fire:
                if controller.direction.x or controller.direction.y:
                    state.value = State.start_attacking
                    state.frame_num = 0
                    continue
