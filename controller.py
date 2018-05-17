from collections import UserList

import pygame
from attr import Factory, attrib, attrs

from system import SystemFlag

player_one = {
    'direction': {
        pygame.K_LEFT: (-1, 0),
        pygame.K_RIGHT: (1, 0),
        pygame.K_UP: (0, -1),
        pygame.K_DOWN: (0, 1),
    },
    'fire': pygame.K_SPACE,
}
player_two = {
    'direction': {
        pygame.K_a: (-1, 0),
        pygame.K_d: (1, 0),
        pygame.K_w: (0, -1),
        pygame.K_s: (0, 1),
    },
    'fire': pygame.K_f,
}


@attrs(slots=True)
class Controller:
    mapping = attrib(type=dict)
    direction = attrib(
        type=pygame.Rect,
        default=Factory(lambda: pygame.Rect(0, 0, 0, 0)),
    )
    fire = attrib(type=bool, default=False)


class ControllerSystem(UserList):
    flags = SystemFlag.controller

    def update(self):
        keys = pygame.key.get_pressed()
        for entity in self.data:
            controller = entity.controller
            controller.direction.topleft = (0, 0)
            for key, value in controller.mapping['direction'].items():
                if keys[key]:
                    controller.direction.x += value[0]
                    controller.direction.y += value[1]
            controller.fire = keys[controller.mapping['fire']]


