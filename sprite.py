import operator
from enum import Enum, auto
from itertools import cycle

from attr import attrs, attrib
import pygame

import assets
from font import pixel_to_surface

x_move_distances = [25, 3, 23, 4] #  , 25]
y_move_up_distances = [2, 9, 2, 9]
y_move_down_distances = [8, 2, 9, 2]


class Move(Enum):
    UP = auto()
    DOWN = auto()
    LEFT = auto()
    RIGHT = auto()
    IDLE = auto()


class Entity(pygame.sprite.Sprite):
    def __init__(self, position, animations, palette, groups=None):
        super().__init__(*groups)
        self.rect = position
        self.animations = {
            name: [make_frame(f, palette) for f in frames]
            for name, frames in animations.items()
        }
        self.groups = groups
        self.palette = palette

        self.image = self.animations['walk'][0].surface

        self.x_move = cycle(x_move_distances)
        self.direction = Move.IDLE
        self.cur_anim = cycle(self.animations['walk'])

    def update(self):
        self.rect.x += next(self.x_move)
        frame = next(self.cur_anim)
        print(self.rect)
        self.image = frame.surface

    def move(self, direction: Move):
        if direction == self.direction:
            self.rect.x += next(self.x_move)
            frame = next(self.cur_anim)
            #print(self.rect)
            self.image = frame.surface

        elif direction == Move.RIGHT:
            self.direction = direction
            self.x_move = cycle(x_move_distances)
            self.cur_anim = cycle(self.animations['walk'])

            self.rect.x += next(self.x_move)
            frame = next(self.cur_anim)
            #print(self.rect)
            self.image = frame.surface
        elif direction == Move.IDLE:
            self.direction = direction
            self.x_move = 0
            self.cur_anim = cycle(self.animations['idle'])





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
    return Frame(frame_surface, frame_rect)


