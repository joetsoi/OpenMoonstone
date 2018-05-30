from collections import UserList

import pygame
from attr import Factory, attrib, attrs


from .movement import Direction
from .entity import Entity
from .system import SystemFlag


@attrs(slots=True)
class AiController:
    opponent = attrib(type=Entity)
    direction = attrib(
        type=pygame.Rect,
        default=Factory(lambda: pygame.Rect(0, 0, 0, 0)),
    )
    fire = attrib(type=bool, default=False)
    close_range = attrib(type=int, default=0)
    long_range = attrib(type=int, default=0)
    y_range = attrib(type=int, default=0)


class AiControllerSystem(UserList):
    flags = SystemFlag.CONTROLLER + SystemFlag.MOVEMENT

    def update(self):
        for entity in self.data:
            controller = entity.controller
            movement = entity.movement

            opponent = controller.opponent

            x_delta = movement.position.x - opponent.movement.position.x
            if x_delta < 0:
                movement.facing = Direction.RIGHT
            elif x_delta > 0:
                movement.facing = Direction.LEFT

            y_delta = movement.position.y - opponent.movement.position.y
            if abs(y_delta) > controller.y_range:
                if y_delta <= 0:
                    controller.direction.y = 1
                elif y_delta > 0:
                    controller.direction.y = -1
            else:
                controller.direction.y = 0
                if abs(x_delta) < controller.close_range:
                    controller.direction.x = movement.facing.value * -1
                elif abs(x_delta) > controller.long_range:
                    controller.direction.x = movement.facing.value
                else:
                    controller.direction.x = 0
