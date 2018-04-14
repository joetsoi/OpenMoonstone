# TODO: Rename to controller to avoid masking built-in input().
from collections import UserList

from attr import attrib, attrs, Factory
import pygame


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
class Input:
    mapping = attrib(type=dict)
    direction = attrib(
        type=pygame.Rect,
        default=Factory(lambda: pygame.Rect(0, 0, 0, 0)),
    )
    fire = attrib(type=bool, default=False)


input_components = []


class InputSystem:
    def update(self):
        keys = pygame.key.get_pressed()
        for input in input_components:
            input.direction.topleft = (0, 0)
            for key, value in input.mapping['direction'].items():
                if keys[key]:
                    input.direction.x += value[0]
                    input.direction.y += value[1]
            input.fire = keys[input.mapping['fire']]


input_system = InputSystem()
