from enum import Enum
from itertools import chain

from attr import attrs, attrib
import pygame

import assets
from assets.animation import Collide
import collide
from input import InputSystem


x_move_distances = (
    (25, 3, 23, 4),
    (0, 0, 0, 0),
    (25, 3, 23, 4),
)
y_move_distances = (
    (2, 9, 2, 9),
    (0, 0, 0, 0),
    (8, 2, 9, 2),
)


class Move(Enum):
    IDLE = (0, 0)
    UP = (0, -1)
    DOWN = (0, 1)
    LEFT = (-1, 0)
    RIGHT = (1, 0)

    LEFT_UP = (-1, -1)
    RIGHT_UP = (1, -1)
    LEFT_DOWN = (-1, 1)
    RIGHT_DOWN = (1, 1)


input_to_animation = {
    Move.IDLE: 'idle',
    Move.UP: 'up',
    Move.DOWN: 'down',
    Move.LEFT: 'walk',
    Move.RIGHT: 'walk',
    Move.LEFT_UP: 'walk',
    Move.RIGHT_UP: 'walk',
    Move.LEFT_DOWN: 'walk',
    Move.RIGHT_DOWN: 'walk',
}


class Direction(Enum):
    LEFT = -1
    RIGHT = 1


BOUNDARY = pygame.Rect(10, 30, 320 - 10, 155 - 30)


class Entity(pygame.sprite.Sprite):
    def __init__(self,
                 position,
                 animations,
                 palette,
                 lair,
                 input: InputSystem,
                 direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.input = input

        self.rect = pygame.Rect(position)
        self.position = pygame.Rect(position)
        self.frames = animations

        self._init_animations(animations, palette)

        self.groups = groups
        self.palette = palette

        self.image = self.animations['idle', Direction.RIGHT][0].surface

        self.move_frame = 0
        self.attack_frame = None

        self.direction = direction

        self.lair = lair

        self.animation_name = None
        self.frame_number = None

    def _init_animations(self, animations: dict, palette):
        self.animations = {
            (name, Direction.RIGHT): [make_frame(f, palette) for f in frames]
            for name, frames in animations.items()
        }
        self.animations.update({
            (name, Direction.LEFT): [
                Frame(
                    surface=pygame.transform.flip(frame.surface,
                                                  True,
                                                  False),
                    rect=frame.rect,
                )
                for frame in animation
            ] for (name, _), animation in self.animations.items()
        })

    def get_images(self):
        return self.frames[self.animation_name][self.frame_number]

    def update(self):
        if self.attack_frame:
            animation_name = 'swing'
            self.update_image(animation_name, self.attack_frame, self.position)
            #self.check_collision()
            collide.attack.add(self)
            self.attack_frame += 1


            animation = self.animations[animation_name, self.direction]
            if self.attack_frame >= len(animation):
                self.attack_frame = None
                collide.attack.remove(self)

        elif self.input.fire:
            self.update_image('swing', 0, self.position)
            #self.check_collision()
            self.attack_frame = 1
            collide.attack.add(self)
        else:
            self.move(self.input.direction)

    def update_image(
            self,
            animation_name: str,
            frame_num: int,
            position: pygame.Rect):
        frame, x = self.get_frame(animation_name, frame_num, position)
        self.set_frame_image(
            animation_name,
            frame_num,
            x,
            position.y + frame.rect.y,
            frame.rect.width,
            frame.rect.height,
            frame.surface,
        )

    def next_frame_position(self, pressed):
        new_position = pygame.Rect(self.position)

        is_moving = (pressed.x | pressed.y) & 1
        move_frame = ((self.move_frame + 1) % 4) * is_moving

        x_delta = x_move_distances[pressed.x + 1][move_frame] * pressed.x
        new_position.x = self.position.x + x_delta

        y_delta = y_move_distances[pressed.y + 1][move_frame] * pressed.y
        new_position.y = self.position.y + y_delta
        return new_position, move_frame

    def clamp_to_boundary(self, pressed, new_position):
        clamped = new_position.clamp(BOUNDARY)
        if clamped.x != new_position.x:
            new_position.x = self.position.x
            pressed.x = 0
        if clamped.y != new_position.y:
            new_position.y = self.position.y
            pressed.y = 0
        return pressed, new_position

    def clamp_to_terrain(self, new_position, frame, frame_num):
        new_rect_y = new_position.y + frame.rect.y + frame.rect.height
        if new_rect_y <= self.lair.terrain_object.boundary.bottom:
            return self.position.y
        return new_position.y

    def get_frame(self, animation_name, frame_number, position):
        frame = self.animations[animation_name, self.direction][frame_number]
        # if we're facing left we want to add frame.rect.width to x
        is_facing_left = int(self.direction.value == Direction.LEFT.value)
        frame_width = frame.rect.width * is_facing_left
        frame_x = self.direction.value * (frame.rect.x + frame_width)
        x = position.x + frame_x
        return frame, x

    def set_frame_image(
            self,
            animation_name: str,
            frame_number: int,
            x: int,
            y: int,
            w: int,
            h:int,
            image: pygame.Surface):
        self.animation_name = animation_name
        self.frame_number = frame_number
        self.rect.x = x
        self.rect.y = y
        self.rect.width = w
        self.rect.height = h
        self.image = image

    def move(self, pressed):
        new_position, move_frame = self.next_frame_position(pressed)
        if pressed.x:
            self.direction = Direction(pressed.x)

        pressed, new_position = self.clamp_to_boundary(pressed, new_position)

        move_frame = move_frame * ((pressed.x | pressed.y) & 1)
        animation_name = input_to_animation[Move((pressed.x, pressed.y))]

        frame, x = self.get_frame(animation_name, move_frame, new_position)
        new_position.y = self.clamp_to_terrain(new_position, frame, move_frame)

        if self.position == new_position:
            frame, x = self.get_frame('idle', 0, new_position)
        else:
            self.position = new_position
            self.move_frame = move_frame

        self.set_frame_image(
            animation_name,
            move_frame,
            x,
            new_position.y + frame.rect.y,
            frame.rect.width,
            frame.rect.height,
            frame.surface,
        )


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
            frame_surface.blit(
                surface,
                (rect.left - frame_rect.left, rect.top - frame_rect.top),
            )
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
                frame_image.x, # - image.x_adjust,
                frame_image.y,
                image.width,
                image.height
            )
        )

    frame_rect = rects[0]
    frame_rect = frame_rect.unionall(rects[1:])
    frame_surface = pygame.Surface(frame_rect.size, pygame.SRCALPHA)
    for rect, surface in zip(rects, surfaces):
        frame_surface.blit(
            surface,
            (rect.left - frame_rect.left, rect.top - frame_rect.top),
        )

    return Frame(frame_surface, frame_rect)
