from enum import Enum

from attr import attrs, attrib
import pygame

import assets
import collide
from input import Input
from movement import Movement, Direction


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


class Entity(pygame.sprite.Sprite):
    def __init__(self,
                 animations,
                 palette,
                 lair,
                 input: Input,
                 movement: Movement,
                 direction: Direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.input = input
        self.movement = movement

        self.rect = pygame.Rect(movement.position)
        self.frames = animations

        self._init_animations(animations, palette)

        self.groups = groups
        self.palette = palette

        self.image = self.animations['idle', Direction.RIGHT][0].surface

        self.attack_frame = None

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
            self.update_image(animation_name, self.attack_frame, self.movement.position)
            collide.attack.add(self)
            self.attack_frame += 1

            animation = self.animations[animation_name, self.movement.direction]
            if self.attack_frame >= len(animation):
                self.attack_frame = None
                collide.attack.remove(self)

        elif self.input.fire:
            self.update_image('swing', 0, self.movement.position)
            self.attack_frame = 1
            collide.attack.add(self)
        else:
            self.move()

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

    def clamp_to_terrain(self, new_position, frame, frame_num):
        new_rect_y = new_position.y + frame.rect.y + frame.rect.height
        if new_rect_y <= self.lair.terrain_object.boundary.bottom:
            return self.position.y
        return new_position.y

    def get_frame(self, animation_name, frame_number, position):
        frame = self.animations[animation_name, self.movement.direction][frame_number]
        # if we're facing left we want to add frame.rect.width to x
        is_facing_left = int(self.movement.direction.value == Direction.LEFT.value)
        frame_width = frame.rect.width * is_facing_left
        frame_x = self.movement.direction.value * (frame.rect.x + frame_width)
        x = position.x + frame_x
        return frame, x

    def set_frame_image(
            self,
            animation_name: str,
            frame_number: int,
            x: int,
            y: int,
            w: int,
            h: int,
            image: pygame.Surface):
        self.animation_name = animation_name
        self.frame_number = frame_number
        self.movement.frame_num = frame_number
        self.rect.x = x
        self.rect.y = y
        self.rect.width = w
        self.rect.height = h
        self.image = image

    def move(self):
        move_frame = self.movement.next_frame
        new_position = self.movement.next_position

        animation_name = input_to_animation[
            Move((self.input.direction.x, self.input.direction.y))
        ]

        frame, x = self.get_frame(animation_name, move_frame, new_position)
        new_position.y = self.clamp_to_terrain(new_position, frame, move_frame)

        if self.movement.position == new_position:
            frame, x = self.get_frame('idle', 0, new_position)
        else:
            self.movement.position = new_position
            self.movement.move_frame = move_frame

        self.set_frame_image(
            animation_name,
            move_frame,
            x,
            new_position.y + frame.rect.y,
            frame.rect.width,
            frame.rect.height,
            frame.surface,
        )


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
                frame_image.x,  # - image.x_adjust,
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
