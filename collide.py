import pygame

from assets.animation import Collide
from assets import collide_hit
from pprint import pprint
import assets

from movement import Direction


rects = []
active = pygame.sprite.Group()
attack = pygame.sprite.Group()


class Collider:
    def __init__(self, animations, collide_data):
        self.defend = {}
        for name, animation in animations.items():
            rects = []
            for frames in animation:
                collidees = [c for c in frames if c.collide == Collide.COLLIDEE]
                rects.append(
                    [Collider._make_image_rect(collidee) for collidee in collidees]
                )
            self.defend[name] = rects

        self.attack = {}
        for name, animation in animations.items():
            rects = []
            for frames in animation:
                colliders = [c for c in frames if c.collide == Collide.COLLIDER]
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
        max = pygame.Rect(
            collider.x,
            collider.y,
            collide_pairs.max[0],
            collide_pairs.max[1],
        )
        return max, collide_rects

    def get_defend_rects(self, animation_name, frame_number):
        return self.defend[animation_name][frame_number]

    def get_attacker_rects(self, attacker):
        return self.attack[attacker.animation_name][attacker.frame_number]

    def get_attack_rects(self, animation_name, image_number):
        return [i[2] for i in self.attack[animation_name][image_number]]

    def get_attack_max(self, animation_name, image_number):
        return [i[1] for i in self.attack[animation_name][image_number]]


def check_collision():
    from graphics import GraphicsSystem
    for attacker in attack:
        for defender in active.sprites():
            if defender == attacker:
                continue

            if abs(attacker.movement.position.y - defender.movement.position.y) >= 10:
                continue

            # if not attacker.rect.colliderect(defender):
            #     continue

            #attack_frame = GraphicsSystem.get_images(attacker)
            #attack_images = [i for i in attack_frame if i.collide == Collide.COLLIDER]

            defender_frame = GraphicsSystem.get_images(defender)
            defender_images = [i for i in defender_frame if i.collide == Collide.COLLIDEE]

            defender_rects = defender.collider.get_defend_rects(
                defender.animation_name, defender.frame_number
            )
            #attack_max = attacker.collider.get_attack_max(attacker.animation_name, attacker.frame_number)
            #collide_list = attacker.collider.get_attack_rects(attacker.animation_name, attacker.frame_number)

            for image_rect, collide_max, collide_rects in attacker.collider.get_attacker_rects(attacker):
            #for a_image_position, max, collide_rects in zip(attack_images, attack_max, collide_list):
                #collide_frame = assets.collide_hit[a_image_position.spritesheet][a_image_position.image_number]
                #a_image = assets.spritesheets[a_image_position.spritesheet].images[a_image_position.image_number]

                max_rect = collide_max.copy()
                attacker_facing_left = int(attacker.movement.direction.value == Direction.LEFT.value)
                max_rect.x += max_rect.width * attacker_facing_left
                max_rect.x *= attacker.movement.direction.value

                max_rect.move_ip(
                    attacker.movement.position.x,
                    attacker.movement.position.y,
                )

                #rects.append(pygame.Rect(max_rect))


                for d_rect, d_image_position in zip(defender_rects, defender_images):
                    defender_rect = d_rect.copy()
                    defender_facing_left = int(defender.movement.direction.value == Direction.LEFT.value)
                    defender_rect.x += defender_rect.width * defender_facing_left
                    defender_rect.x *= defender.movement.direction.value

                    defender_rect.move_ip(
                        defender.movement.position.x,
                        defender.movement.position.y
                    )
                    rects.append(pygame.Rect(defender_rect))
                # for d_image_position in defender_images:
                #     d_image = assets.spritesheets[d_image_position.spritesheet].images[d_image_position.image_number]
                #     defender_rect.x = defender.movement.position.x + d_image_position.x
                #     defender_rect.y = defender.movement.position.y + d_image_position.y
                #     defender_rect.width = d_image.width
                #     defender_rect.height = d_image.height

                    #rects.append(pygame.Rect(defender_rect))
                    #print(rects)
                    # print(defender_rect)

                    if not max_rect.colliderect(defender_rect):
                        continue

                    #for (x, y), a_rects in zip(collide_frame, collide_rects):
                    for a_rects in collide_rects:
                        attacker_rect = a_rects.copy()
                        attacker_rect.x += attacker_rect.width * attacker_facing_left
                        attacker_rect.x *= attacker.movement.direction.value

                        attacker_rect.move_ip(
                            attacker.movement.position.x,
                            attacker.movement.position.y,
                        )
                        rects.append(pygame.Rect(attacker_rect))
                        # attack_rect.left = attacker.movement.position.x + a_image_position.x# + a_image.width - x
                        # attack_rect.top =  attacker.movement.position.y + a_image_position.y
                        # attack_rect.width = x
                        # attack_rect.height = y
                        # assert attack_rect == attacker_rect

                        if not attacker_rect.colliderect(defender_rect):
                            continue

                        attack_x = attacker_rect.right#attacker.movement.position.x + a_image_position.x + x
                        attack_y = attacker_rect.bottom#attacker.movement.position.y + a_image_position.y + y
                        def_x = defender_rect.x
                        def_y = defender_rect.y

                        pixel = (attack_y - def_y) * d_rect.width + (attack_x - def_x)

                        d_image = assets.spritesheets[d_image_position.spritesheet].images[d_image_position.image_number]
                        pixel = d_image.pixels[pixel]
                        if pixel:
                            #rects.append(pygame.Rect(attacker_rect))
                            print("collide")

if __name__ == '__main__':
    for c in collide_hit['kn4.ob']:
        pprint(c.max)
        print(c)
