from enum import Enum
from collections import UserList

from attr import attrs, attrib
import pygame

import assets
import collide
from movement import Movement, Direction
from input import Input


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


def make_animations(animations: dict, palette):
    animations = {
        (name, Direction.RIGHT): [
            Frame.from_frame_images(f, palette) for f in frames
        ]
        for name, frames in animations.items()
    }
    animations.update({
        (name, Direction.LEFT): [
            Frame(
                surface=pygame.transform.flip(frame.surface,
                                              True,
                                              False),
                rect=frame.rect,
            )
            for frame in animation
        ] for (name, _), animation in animations.items()
    })
    return animations


class Graphic(pygame.sprite.Sprite):
    def __init__(self,
                 input: Input,
                 movement: Movement,
                 animations,
                 palette,
                 lair,
                 direction: Direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.input = input
        self.movement = movement

        self.rect = pygame.Rect(movement.position)
        self.frames = animations

        self.animations = make_animations(animations, palette)

        self.groups = groups

        self.image = self.animations['idle', Direction.RIGHT][0].surface

        self.lair = lair
        self.animation_name = None


class GraphicsSystem(UserList):
    def update(self):
        for graphic in self.data:

            if graphic.movement.attack_frame:
                animation_name = 'swing'

                animation = graphic.animations[animation_name,
                                               graphic.movement.direction]
                if graphic.movement.attack_frame == len(animation) - 1:
                    collide.attack.remove(graphic)

                GraphicsSystem.update_image(
                    graphic,
                    animation_name,
                    graphic.movement.attack_frame,
                    graphic.movement.position,
                )

            elif graphic.input.fire:
                GraphicsSystem.update_image(
                    graphic,
                    'swing',
                    graphic.movement.attack_frame,
                    graphic.movement.position,
                )
                animation = graphic.animations['swing',
                                               graphic.movement.direction]
                graphic.movement.attack_anim_length = len(animation)
                collide.attack.add(graphic)
            else:
                GraphicsSystem.move(graphic)

    @staticmethod
    def get_images(graphic):
        return graphic.frames[graphic.animation_name][graphic.frame_number]

    @staticmethod
    def update_image(
            graphic,
            animation_name: str,
            frame_num: int,
            position: pygame.Rect):
        frame, x = GraphicsSystem.get_frame(
            graphic,
            animation_name,
            frame_num,
            position,
        )
        GraphicsSystem.set_frame_image(
            graphic,
            animation_name,
            frame_num,
            x,
            position.y + frame.rect.y,
            frame.rect.width,
            frame.rect.height,
            frame.surface,
        )

    @staticmethod
    def clamp_to_terrain(graphic, new_position, frame, frame_num):
        new_rect_y = new_position.y + frame.rect.y + frame.rect.height
        if new_rect_y <= graphic.lair.terrain_object.boundary.bottom:
            return graphic.movement.position.y
        return new_position.y

    @staticmethod
    def get_frame(graphic, animation_name, frame_number, position):
        frame = graphic.animations[animation_name, graphic.movement.direction][frame_number]
        # if we're facing left we want to add frame.rect.width to x
        is_facing_left = int(graphic.movement.direction.value == Direction.LEFT.value)
        frame_width = frame.rect.width * is_facing_left
        frame_x = graphic.movement.direction.value * (frame.rect.x + frame_width)
        x = position.x + frame_x
        return frame, x

    @staticmethod
    def set_frame_image(
            graphic,
            animation_name: str,
            frame_number: int,
            x: int,
            y: int,
            w: int,
            h: int,
            image: pygame.Surface):
        graphic.animation_name = animation_name
        graphic.frame_number = frame_number
        graphic.movement.frame_num = frame_number
        graphic.rect.x = x
        graphic.rect.y = y
        graphic.rect.width = w
        graphic.rect.height = h
        graphic.image = image

    @staticmethod
    def move(graphic):
        move_frame = graphic.movement.next_frame
        new_position = graphic.movement.next_position

        animation_name = input_to_animation[
            Move((graphic.input.direction.x, graphic.input.direction.y))
        ]

        frame, x = GraphicsSystem.get_frame(graphic, animation_name, move_frame, new_position)
        new_position.y = GraphicsSystem.clamp_to_terrain(graphic, new_position, frame, move_frame)

        # TODO: move this to movement.py
        if graphic.movement.position == new_position:
            frame, x = GraphicsSystem.get_frame(graphic, 'idle', 0, new_position)
        else:
            graphic.movement.position = new_position
            graphic.movement.move_frame = move_frame

        GraphicsSystem.set_frame_image(
            graphic,
            animation_name,
            move_frame,
            x,
            new_position.y + frame.rect.y,
            frame.rect.width,
            frame.rect.height,
            frame.surface,
        )

graphics_system = GraphicsSystem()
