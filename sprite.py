from enum import Enum

from attr import attrs, attrib
import pygame

import assets


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


DIRECTION = {
    pygame.K_LEFT: (-1, 0),
    pygame.K_RIGHT: (1, 0),
    pygame.K_UP: (0, -1),
    pygame.K_DOWN: (0, 1),
}

FIRE = pygame.K_SPACE


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
                 direction=Direction.RIGHT,
                 groups=None):
        super().__init__(*groups)
        self.rect = pygame.Rect(position)
        self.position = pygame.Rect(position)
        self.frames = animations
        self.animations = {
            (name, Direction.RIGHT): [make_frame(f, palette) for f in frames]
            for name, frames in animations.items()
        }
        left_animations = {
           (name, Direction.LEFT): [
                Frame(
                    surface=pygame.transform.flip(frame.surface,
                                                  True,
                                                  False),
                    rect=frame.rect,
                )
                for frame in animation
            ] for (name, _), animation in self.animations.items()
        }
        self.animations.update(left_animations)

        self.groups = groups
        self.palette = palette

        self.image = self.animations['idle', Direction.RIGHT][0].surface

        self.move_frame = 0
        self.attack_frame = None

        self.input = pygame.Rect(0, 0, 0, 0)
        self.direction = direction

        self.lair = lair

        self.current_animation = None
        self.current_frame_number = None

    def update(self):
        keys = pygame.key.get_pressed()
        pressed = pygame.Rect(0, 0, 0, 0)
        for key, value in DIRECTION.items():
            if keys[key]:
                pressed.x += value[0]
                pressed.y += value[1]

        if self.attack_frame:
            animation_name = 'swing'
            self.update_image(animation_name, self.attack_frame, self.position)
            self.attack_frame += 1

            animation = self.animations[animation_name, self.direction]
            if self.attack_frame >= len(animation):
                self.attack_frame = None

        elif keys[FIRE]:
            self.update_image('swing', 0, self.position)
            self.attack_frame = 1
        else:
            self.move(pressed)

    def update_image(
            self,
            animation_name: str,
            frame_num: int,
            position: pygame.Rect):
        frame, x = self.get_frame(animation_name, frame_num, position)

        self.rect.x = x
        self.rect.y = position.y + frame.rect.y
        self.rect.width = frame.rect.width
        self.rect.height = frame.rect.height
        self.image = frame.surface

    def calculate_next_frame_position(self, pressed):
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

    def move(self, pressed):
        new_position, move_frame = self.calculate_next_frame_position(pressed)
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

        self.rect.x = x
        self.rect.y = new_position.y + frame.rect.y
        self.rect.width = frame.rect.width
        self.rect.height = frame.rect.height
        self.image = frame.surface
        self.input = pressed


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
