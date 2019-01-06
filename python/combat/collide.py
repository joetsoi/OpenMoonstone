from collections import UserList

import pygame
from attr import attrib, attrs

import assets
import settings
from assets.animation import FrameType

# from .graphics import Graphic
from .movement import Direction, Movement
from .state import State
from .system import SystemFlag

# from pprint import pprint




attack = pygame.sprite.Group()


class Collider:
    def __init__(self, animations, collide_data):
        self.defend = {}
        for name, animation in animations.items():
            rects = []
            for frame in animation:
                collidees = [c for c in frame if c.collide == FrameType.COLLIDEE]
                rects.append(
                    [Collider._make_image_rect(collidee) for collidee in collidees]
                )
            self.defend[name] = rects

        self.attack = {}
        for name, animation in animations.items():
            rects = []
            for frame in animation:
                colliders = [c for c in frame if c.collide == FrameType.COLLIDER]
                rects.append([
                    (
                        Collider._make_image_rect(collider),
                        *Collider._make_collide_rect(collider, collide_data),
                    )
                    for collider in colliders
                ])
            self.attack[name] = rects

    @staticmethod
    def _make_image_rect(image_position):
        sprite_sheet = assets.spritesheets[image_position.spritesheet]
        image = sprite_sheet.images[image_position.image_number]
        return pygame.Rect(
            image_position.x,
            image_position.y,
            image.width,
            image.height
        )

    @staticmethod
    def _make_collide_rect(collider, collide_data):
        collide_pairs = collide_data[collider.spritesheet][collider.image_number]
        collide_rects = [
            pygame.Rect(collider.x, collider.y, x, y)
            for x, y in collide_pairs
        ]
        if collide_pairs:
            max_rect = pygame.Rect(
                collider.x,
                collider.y,
                collide_pairs.max[0],
                collide_pairs.max[1],
            )
        else:
            max_rect = pygame.Rect(collider.x, collider.y, 0, 0)
        return max_rect, collide_rects

    def get_defend_rects(self, animation_name, frame_number):
        return self.defend[animation_name][frame_number]

    def get_attacker_rects(self, attacker):
        rects = self.attack[attacker.animation_name]
        if rects:
            return rects[attacker.frame_number]
        else:
            return []

    def get_attack_rects(self, animation_name, image_number):
        return [i[2] for i in self.attack[animation_name][image_number]]

    def get_attack_max(self, animation_name, image_number):
        return [i[1] for i in self.attack[animation_name][image_number]]


@attrs(slots=True)
class Collision:
    collider = attrib(type=Collider)
    has_hit = attrib(type='Entity', default=None)


class CollisionSystem(UserList):
    flags = SystemFlag.MOVEMENT + SystemFlag.GRAPHICS + SystemFlag.COLLISION + SystemFlag.ANIMATIONSTATE

    def __init__(self, initlist=None):
        super().__init__(initlist)
        self.debug_rects = []

    def update(self):
        # attackers = [e for e in self.data if e.graphics.is_attacking]
        attackers = [e for e in self.data if e.state.value == State.attacking]
        for attacker in attackers:
            attacker.collision.has_hit = None
            for defender in self.data:
                collided = check_collision(self, attacker, defender)
                if collided:
                    attacker.collision.has_hit = defender


def check_collision(system, attacker, defender):
    if defender == attacker:
        return False

    if abs(attacker.movement.position.y - defender.movement.position.y) >= 10:
        return False

    defender_frame = defender.graphics.get_images()
    defender_images = [i for i in defender_frame if i.collide == FrameType.COLLIDEE]

    defender_rects = defender.collision.collider.get_defend_rects(
        defender.graphics.animation_name, defender.graphics.frame_number
    )

    for attacker_rects in attacker.collision.collider.get_attacker_rects(attacker.graphics):
        image_rect, collide_max, collide_rects = attacker_rects
        max_rect = get_entity_collision_rect(attacker.movement, collide_max)

        if settings.DEBUG:
            system.debug_rects.append(pygame.Rect(max_rect))

        for d_rect, d_image_position in zip(defender_rects, defender_images):
            defender_rect = get_entity_collision_rect(defender.movement, d_rect)
            if settings.DEBUG:
                system.debug_rects.append(pygame.Rect(defender_rect))

            if not max_rect.colliderect(defender_rect):
                continue

            for attacker_rect in collide_rects:
                attacker_rect = get_entity_collision_rect(attacker.movement, attacker_rect)
                if settings.DEBUG:
                    system.debug_rects.append(pygame.Rect(attacker_rect))

                if not attacker_rect.colliderect(defender_rect):
                    continue

                collided = check_pixel_collision(
                    attacker_rect,
                    defender_rect,
                    d_image_position,
                )
                if collided:
                    return True


def get_entity_collision_rect(movement: Movement, rect):
    rect = rect.copy()
    is_facing_left = int(movement.facing.value == Direction.LEFT.value)
    rect.x += rect.width * is_facing_left
    rect.x *= movement.facing.value

    rect.move_ip(
        movement.position.x,
        movement.position.y,
    )
    return rect


def check_pixel_collision(attacker_rect, defender_rect, defender_image_position):
    attack_x = attacker_rect.right
    attack_y = attacker_rect.bottom
    def_x = defender_rect.x
    def_y = defender_rect.y

    pixel = (attack_y - def_y) * defender_rect.width + (attack_x - def_x)

    d_image = assets.spritesheets[defender_image_position.spritesheet].images[defender_image_position.image_number]
    pixel = d_image.pixels[pixel]
    if pixel:
        #rects.append(pygame.Rect(attacker_rect))
        #print("collide")
        return True
