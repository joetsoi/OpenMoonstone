from collections import UserList
from enum import Enum
from typing import List, Optional

import pygame
from attr import attrib, attrs

import assets
from controller import Controller
#import collide
#from collide import Collider
from movement import Direction, Movement

active = pygame.sprite.Group()


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


controller_to_animation = {
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


@attrs(slots=True)
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


@attrs(slots=True, auto_attribs=True)
class Animation:
    frames: List[Frame]
    order: Optional[List[int]] = None


def make_animations(animation_definitions: dict, palette):
    def make_order(frames, order):
        if not order:
            order = list(range(len(frames)))
        return list(order)

    animations = {
        (name, Direction.RIGHT): Animation(
            frames=[
                Frame.from_frame_images(f, palette) for f in animation.frames
            ],
            order=make_order(animation.frames, animation.order),
        ) for name, animation in animation_definitions.items()
    }
    animations.update({
        (name, Direction.LEFT): Animation(
            frames=[
                Frame(
                    surface=pygame.transform.flip(frame.surface,
                                                  True,
                                                  False),
                    rect=frame.rect,
                )
                for frame in animation.frames
            ],
            order=animation.order,
        ) for (name, _), animation in animations.items()
    })
    return animations


class Graphic(pygame.sprite.Sprite):
    def __init__(self,
                 controller: Controller,
                 movement: Movement,
                 #collider: Collider,
                 animations,
                 palette,
                 lair,
                 direction: Direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.controller = controller
        self.movement = movement
        #self.collider = collider

        self.rect = pygame.Rect(movement.position)
        self.frames = animations

        self.animations = make_animations(animations, palette)

        self.groups = groups

        self.image = self.animations['idle', Direction.RIGHT].frames[0].surface

        self.lair = lair
        self.animation_name = None
        self.has_hit = None

        self.is_attacking = False

    def get_images(self):
        animation = self.frames[self.animation_name]
        return animation[self.frame_number]

    def update_image(
            self,
            animation_name: str,
            frame_num: int,
            position: pygame.Rect):
        frame, x = self.get_frame(
            animation_name,
            frame_num,
            position,
        )
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
            return self.movement.position.y
        return new_position.y

    def get_frame(self, animation_name, frame_number, position):
        animation = self.animations[animation_name, self.movement.direction]
        frame_number = animation.order[frame_number]
        frame = animation.frames[frame_number]

        direction = self.movement.direction
        # if we're facing left we want to add frame.rect.width to x
        is_facing_left = int(direction.value == Direction.LEFT.value)
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

        animation_name = controller_to_animation[
            Move((self.controller.direction.x, self.controller.direction.y))
        ]

        frame, x = self.get_frame(animation_name, move_frame, new_position)
        new_position.y = self.clamp_to_terrain(new_position, frame, move_frame)

        # TODO: move this to movement.py
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


class GraphicsSystem(UserList):
    def update(self):
        for graphic in self.data:
            if graphic.movement.attack_frame:
                animation_name = 'swing'

                animation = graphic.animations[animation_name,
                                               graphic.movement.direction]
                if graphic.movement.attack_frame == len(animation.order) - 1:
                    graphic.is_attacking = False
                    #collide.attack.remove(graphic)

                graphic.update_image(
                    animation_name,
                    graphic.movement.attack_frame,
                    graphic.movement.position,
                )

            elif graphic.controller.fire:
                graphic.update_image(
                    'swing',
                    graphic.movement.attack_frame,
                    graphic.movement.position,
                )
                animation = graphic.animations['swing',
                                               graphic.movement.direction]
                graphic.movement.attack_anim_length = len(animation.order)
                graphic.is_attacking = True
                #collide.attack.add(graphic)
            else:
                graphic.move()


graphics_system = GraphicsSystem()
