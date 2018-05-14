from collections import UserList

import pygame
from attr import attrib, attrs

import assets
from assets.animation import FrameType
from entity import Entity
from graphics import Frame
from movement import Direction
from state import AnimationState, State, state_system
from system import SystemFlag

blood_stains = pygame.sprite.Group()


def get_blood_frames(
        animations: dict,
        animation_name: str):

    animation = animations[animation_name]
    frames = []
    for frame in animation:
        blood = [b for b in frame if b.collide == FrameType.BLOOD_STAIN]
        frames.append(blood)
    return frames


@attrs(slots=True)
class BloodStain:
    position = attrib(
        type=pygame.Rect,
        converter=lambda p: pygame.Rect(p[0], p[1], 0, 0),
    )
    frames = attrib()
    palette = attrib()
    facing = attrib(type=Direction, default=Direction.RIGHT)


class BloodGraphic(pygame.sprite.Sprite):
    def __init__(self, blood_stain: BloodStain, frame_num: int) -> None:
        super().__init__([blood_stains])

        direction = blood_stain.facing
        position = blood_stain.position
        frame = Frame.from_frame_images(
            blood_stain.frames[frame_num],
            blood_stain.palette
        )

        # if we're facing left we want to add frame.rect.width to x
        is_facing_left = int(direction.value == Direction.LEFT.value)
        frame_width = frame.rect.width * is_facing_left
        frame_x = direction.value * (frame.rect.x + frame_width)
        x = position.x + frame_x
        y = position.y + frame.rect.y
        self.rect = pygame.Rect(x, y, frame.rect.width, frame.rect.height)
        if is_facing_left:
            self.image = pygame.transform.flip(frame.surface, True, False)
        else:
            self.image = frame.surface


class BloodSystem(UserList):
    flags = SystemFlag.state + SystemFlag.blood

    def update(self, background):
        for entity in self.data:
            blood = entity.blood
            state = entity.state

            draw_blood = state.value != State.destroy and state.frame_num > 0
            if draw_blood and blood.frames[state.frame_num]:
                for stain in blood.frames:
                    BloodGraphic(blood, state.frame_num)
        blood_stains.draw(background)
        blood_stains.empty()



blood_system = BloodSystem()


def create_knight_blood_stain(animation_name, palette, facing, position):
    frames = get_blood_frames(assets.animation.knight, animation_name)
    blood_entity = Entity(
        blood=BloodStain(position, frames, palette, facing),
        state=AnimationState(-1, animation_name, len(frames), State.loop_once),
    )
    blood_system.append(blood_entity)
    state_system.append(blood_entity)
