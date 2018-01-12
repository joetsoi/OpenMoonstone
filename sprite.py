import operator
from enum import Enum, auto
from functools import partial

from attr import attrs, attrib
import pygame

import assets
from font import pixel_to_surface

x_move_distances = [25, 3, 23, 4] #  , 25]
y_move_up_distances = [2, 9, 2, 9]
y_move_down_distances = [8, 2, 9, 2]

DIRECTION = {
    pygame.K_LEFT: (-1, 0),
    pygame.K_RIGHT: (1, 0),
    pygame.K_UP: (0, -1),
    pygame.K_DOWN: (0, 1),
}


class Move(Enum):
    UP = auto()
    DOWN = auto()
    LEFT = auto()
    RIGHT = auto()
    IDLE = auto()


class Direction(Enum):
    LEFT = auto()
    RIGHT = auto()


BOUNDARY = pygame.Rect(10, 30, 320 - 10, 155 - 30)


def mod3(n):
    return (n + 1) % 3

class Entity(pygame.sprite.Sprite):
    def __init__(self,
                 position,
                 animations,
                 palette,
                 lair,
                 direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.rect = pygame.Rect(position)
        self.position = pygame.Rect(position)
        self.animations = {
            name: [make_frame(f, palette) for f in frames]
            for name, frames in animations.items()
        }
        left_animations = {
           f'{name}_left': [
                Frame(
                    surface=pygame.transform.flip(frame.surface,
                                                  True,
                                                  False),
                    rect=frame.rect,
                )
                for frame in animation
            ] for name, animation in self.animations.items()
        }
        self.animations.update(left_animations)

        self.groups = groups
        self.palette = palette

        self.image = self.animations['idle'][0].surface

        self.move = 0

        self.input = pygame.Rect(0, 0, 0, 0)
        self.direction = direction

        self.lair = lair

    def update(self):
        keys = pygame.key.get_pressed()
        pressed = pygame.Rect(0, 0, 0, 0)
        for key, value in DIRECTION.items():
            if keys[key]:
                pressed.x += value[0]
                pressed.y += value[1]

        new_position = pygame.Rect(self.position)
        if pressed.x == 0 and pressed.y == 0:
            animation_name = 'idle'
            frame_num = 0
        else:
            self.move = (self.move + 1) % 4
            frame_num = self.move

        if pressed.y == 1:
            new_position.y = self.position.y + y_move_down_distances[frame_num]
            animation_name = 'down'

        elif pressed.y == -1:
            new_position.y = self.position.y - y_move_up_distances[frame_num]
            animation_name = 'up'

        if pressed.x == 1:
            new_position.x = self.position.x + x_move_distances[frame_num]
            animation_name = 'walk'
            self.direction = Direction.RIGHT

        elif pressed.x == -1:
            new_position.x = self.position.x - x_move_distances[frame_num]
            animation_name = 'walk'
            self.direction = Direction.LEFT

        clamped = new_position.clamp(BOUNDARY)
        if clamped != new_position:
            animation_name = 'idle'
            frame_num = 0
            self.position = clamped

        if self.direction == Direction.LEFT:
            animation_name = f'{animation_name}_left'

            frame = self.animations[animation_name][frame_num]
            self.rect.x = new_position.x - (frame.rect.x + frame.rect.width)
        else:
            frame = self.animations[animation_name][frame_num]
            self.rect.x = new_position.x + frame.rect.x

        self.rect.width = frame.rect.width
        self.rect.height = frame.rect.height

        new_rect_y = new_position.y + frame.rect.y + frame.rect.height


        print(self.rect.bottom, self.lair.terrain_object.boundary.bottom, new_rect_y)
        if new_rect_y <= self.lair.terrain_object.boundary.bottom:
            print(new_position.y)
            print(self.position.y)
            new_position.y = self.position.y

        self.rect.y = new_position.y + frame.rect.y
        self.input = pressed
        self.image = frame.surface
        self.position = new_position


class Player(Entity):
    def update(self):
        pass


@attrs
class Frame:
    surface = attrib()
    rect = attrib()

    @classmethod
    def from_frame_images(cls, frame_images, palette):
        surfaces = []
        rects = []
        for frame_image in frame_images:
            spritesheet = assets.spritesheets[frame_image.spritesheet]
            image = spritesheet.images[frame_image.image_number]
            surfaces.append(image.to_surface(palette))
            rects.append(
                pygame.Rect(
                    frame_image.x,
                    frame_image.y,
                    image.width,
                    image.height
                )
            )

        frame_rect = rects[0]
        frame_rect = frame_rect.unionall(rects[1:])
        frame_surface = pygame.Surface(frame_rect.size, pygame.SRCALPHA)
        for rect, surface in zip(rects, surfaces):
            frame_surface.blit(surface, (rect.left - frame_rect.left, rect.top - frame_rect.top))
        return cls(frame_surface, frame_rect)


def make_frame(frame_images, palette):
    surfaces = []
    rects = []
    for frame_image in frame_images:
        spritesheet = assets.spritesheets[frame_image.spritesheet]
        image = spritesheet.images[frame_image.image_number]
        surfaces.append(image.to_surface(palette))
        rects.append(
            pygame.Rect(
                # TODO: determine whether x_adjust is needed
                frame_image.x - image.x_adjust,
                frame_image.y,
                image.width,
                image.height
            )
        )

    frame_rect = rects[0]
    frame_rect = frame_rect.unionall(rects[1:])
    frame_surface = pygame.Surface(frame_rect.size, pygame.SRCALPHA)
    for rect, surface in zip(rects, surfaces):
        frame_surface.blit(surface, (rect.left - frame_rect.left, rect.top - frame_rect.top))

    return Frame(frame_surface, frame_rect)
