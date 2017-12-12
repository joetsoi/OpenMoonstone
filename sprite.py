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


def mod3(n):
    return (n + 1) % 3

class Entity(pygame.sprite.Sprite):
    def __init__(self,
                 position,
                 animations,
                 palette,
                 direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.rect = pygame.Rect(position)
        self.position = pygame.Rect(position)
        self.animations = {
            name: [make_frame(f, palette) for f in frames]
            for name, frames in animations.items()
        }
        print("walk: ", [f.rect for f in self.animations['walk']])
        print("walk: ", [f.surface.get_width() for f in self.animations['walk']])
        self.animations['left'] = [
            Frame(
                surface=pygame.transform.flip(frame.surface,
                                              True,
                                              False),
                rect=frame.rect,
            )
            for frame in self.animations['walk']
        ]
        self.animations['idle_left'] = [
            Frame(
                surface=pygame.transform.flip(frame.surface,
                                              True,
                                              False),
                rect=frame.rect,
            )
            for frame in self.animations['idle']
        ]
        self.groups = groups
        self.palette = palette

        self.image = self.animations['idle'][0].surface

        self.x_move = 0#cycle(x_move_distances)
        self.y_move = 0#cycle(y_move_up_distances)

        self.input = pygame.Rect(0, 0, 0, 0)
        self.cur_anim = self.animations['idle'][0]
        self.direction = direction

    def update(self):
        keys = pygame.key.get_pressed()
        pressed = pygame.Rect(0, 0, 0, 0)
        for key, value in DIRECTION.items():
            if keys[key]:
                pressed.x += value[0]
                pressed.y += value[1]
        #print(pressed)

        if pressed.y == 1:
            if pressed.y != self.input.y:
                self.y_move = 0#cycle(y_move_down_distances)
            else:
                self.y_move  = (self.y_move + 1) % 3

            self.position.y += y_move_down_distances[self.y_move]
            frame = self.animations['down'][self.y_move]

        elif pressed.y == -1:
            if pressed.y != self.input.y:
                self.y_move = 0#cycle(y_move_down_distances)
            else:
                self.y_move  = (self.y_move + 1) % 3
            self.position.y -= y_move_up_distances[self.y_move]
            frame = self.animations['up'][self.y_move]

        if pressed.x == 1:
            if pressed.x != self.input.x:
                self.x_move = 0
            else:
                self.x_move  = (self.x_move + 1) % 3
            self.position.x += x_move_distances[self.x_move]

            self.direction = Direction.RIGHT
            frame = self.animations['walk'][self.x_move]

        elif pressed.x == -1:
            if pressed.x != self.input.x:
                self.x_move = 0
            else:
                self.x_move  = (self.x_move + 1) % 3
            self.position.x -= x_move_distances[self.x_move]
                # self.cur_anim = cycle([
                #     Frame(
                #         surface=pygame.transform.flip(frame.surface,
                #                                       True,
                #                                       False),
                #         rect=pygame.Rect(
                #             frame.rect.x,# - frame.rect.width,
                #             frame.rect.y,
                #             frame.rect.width,
                #             frame.rect.height,
                #             ),
                #     )
                #     for frame in self.animations['walk']
                # ])
            self.direction = Direction.LEFT
            frame = self.animations['left'][self.x_move]
            #self.rect.x = self.position.x - frame.surface.get_width()
            #self.rect.x = self.position.x# - frame.surface.get_width()

            #print(self.rect.x, frame.surface.get_width())

        if pressed.x == 0 and pressed.y == 0:
            if self.direction == Direction.LEFT:
                #print(self.position)
                frame = self.animations['idle_left'][0]
            else:
                frame = self.animations['idle'][0]


        if self.direction == Direction.LEFT:
            self.rect.x = self.position.x - (frame.rect.x + frame.rect.width)
            self.rect.y = self.position.y + frame.rect.y
        else:
            self.rect.x = self.position.x + frame.rect.x
            self.rect.y = self.position.y + frame.rect.y

        self.input = pressed
        #print(self.position)
        self.image = frame.surface


    def move(self, direction):
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


def flip_animation(frames):
    max_x = max(frames, key=lambda rect: rect.width)
    flipped = [
        Frame(
            surface=pygame.transform.flip(frame.surface,
                                          True,
                                          False),
            rect=pygame.Rect(
                frame.rect.x,
                frame.rect.y,
                frame.rect.width,
                frame.rect.height,
            ),
        )
        for frame in frames
    ]
    return flipped
