from collections import UserList
from enum import auto, Enum

import pygame
from attr import attrib, attrs

from system import SystemFlag

x_distances = (
    (25, 3, 23, 4),
    (0, 0, 0, 0),
    (25, 3, 23, 4),
)
y_distances = (
    (2, 9, 2, 9),
    (0, 0, 0, 0),
    (8, 2, 9, 2),
)
BOUNDARY = pygame.Rect(10, 30, 320 - 10, 155 - 30)


class Direction(Enum):
    LEFT = -1
    RIGHT = 1


class State(Enum):
    walking = auto()
    start_attacking = auto()
    attacking = auto()
    busy = auto()


@attrs(slots=True)
class Movement:
    position = attrib(
        type=pygame.Rect,
        converter=lambda p: pygame.Rect(p[0], p[1], 0, 0),
    )
    frame_num = attrib(type=int, default=0)
    facing = attrib(type=Direction, default=Direction.RIGHT)

    next_position = attrib(
        type=pygame.Rect,
        default=lambda: pygame.Rect(0, 0, 0, 0),
    )
    next_frame = attrib(type=int, default=0)
    #move_frame = attrib(type=int, default=0)

    attack_frame = attrib(type=int, default=None)
    attack_anim_length = attrib(type=int, default=None)

    state = attrib(type=State, default=State.walking)

    def get_next_position(self, direction):
        new_position = pygame.Rect(self.position)

        is_moving = (direction.x | direction.y) & 1
        move_frame = ((self.frame_num + 1) % 4) * is_moving

        x_delta = x_distances[direction.x + 1][move_frame] * direction.x
        new_position.x = self.position.x + x_delta

        y_delta = y_distances[direction.y + 1][move_frame] * direction.y
        new_position.y = self.position.y + y_delta
        return new_position, move_frame

    def clamp_to_boundary(self, direction, new_position):
        x = direction.x
        y = direction.y

        clamped = new_position.clamp(BOUNDARY)
        if clamped.x != new_position.x:
            new_position.x = self.position.x
            x = 0
        if clamped.y != new_position.y:
            new_position.y = self.position.y
            y = 0
        return x, y, new_position


class MovementSystem(UserList):
    flags = SystemFlag.controller + SystemFlag.movement

    def update(self):
        for entity in self.data:
            mover = entity.movement
            controller = entity.controller

            if mover.state == State.busy:
                continue

            if mover.attack_frame is not None:
                mover.attack_frame += 1
                if mover.attack_frame < mover.attack_anim_length:
                    continue
                else:
                    mover.attack_frame = None
                    mover.attack_anim_length = None
                    mover.state = State.walking

            if controller.fire:
                mover.state = State.start_attacking
                mover.attack_frame = 0
                continue

            direction = controller.direction
            new_position, frame = mover.get_next_position(direction)
            if direction.x:
                mover.facing = Direction(controller.direction.x)

            x, y, new_position = mover.clamp_to_boundary(direction,
                                                         new_position)
            direction.x = x
            direction.y = y

            frame = frame * ((direction.x | direction.y) & 1)
            mover.next_frame = frame
            mover.next_position = new_position
            mover.state = State.walking


movement_system = MovementSystem()
