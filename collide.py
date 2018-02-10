import pygame

from assets.animation import Collide
from assets import collide_hit
from pprint import pprint
import assets


rects = []
active = pygame.sprite.Group()
attack = pygame.sprite.Group()


def check_collision():
    for attacker in attack:
        for defender in active.sprites():
            if defender == attacker:
                continue

            if abs(attacker.position.y - defender.position.y) >= 10:
                continue

            # if not attacker.rect.colliderect(defender):
            #     continue

            attack_frame = attacker.get_images()
            attack_images = [i for i in attack_frame if i.collide == Collide.COLLIDER]
            #print(attack_images)
            attack_rect = pygame.Rect(0, 0, 0, 0)


            defender_frame = defender.get_images()
            defender_images = [i for i in defender_frame if i.collide == Collide.COLLIDEE]
            defender_rect = pygame.Rect(0, 0, 0, 0)

            for a_image_position in attack_images:
                collide_frame = assets.collide_hit[a_image_position.spritesheet][a_image_position.image_number]
                # attack_rect.left = attacker.rect.right# - collide_frame.max[0]
                # attack_rect.top =  attacker.rect.top
                #attack_rect.left = attacker.position.x + image_position.x + collide_frame.max[0]
                a_image = assets.spritesheets[a_image_position.spritesheet].images[a_image_position.image_number]
                attack_rect.left = attacker.position.x + a_image_position.x #- collide_frame.max[0]
                attack_rect.top =  attacker.position.y + a_image_position.y
                attack_rect.width = collide_frame.max[0]
                attack_rect.height = collide_frame.max[1]
                #rects.append(pygame.Rect(attack_rect))

                for d_image_position in defender_images:
                    d_image = assets.spritesheets[d_image_position.spritesheet].images[d_image_position.image_number]
                    defender_rect.x = defender.position.x + d_image_position.x
                    defender_rect.y = defender.position.y + d_image_position.y
                    defender_rect.width = d_image.width
                    defender_rect.height = d_image.height

                    #rects.append(pygame.Rect(defender_rect))
                    #print(rects)

                    if not attack_rect.colliderect(defender_rect):
                        continue

                    for x, y in collide_frame:
                        attack_rect.left = attacker.position.x + a_image_position.x# + a_image.width - x
                        attack_rect.top =  attacker.position.y + a_image_position.y
                        attack_rect.width = x
                        attack_rect.height = y

                        if not attack_rect.colliderect(defender_rect):
                            continue

                        attack_x = attacker.position.x + a_image_position.x + x
                        attack_y = attacker.position.y + a_image_position.y + y
                        def_x = defender_rect.x
                        def_y = defender_rect.y

                        pixel = (attack_y - def_y) * d_image.width + (attack_x - def_x)
                        pixel = d_image.pixels[pixel]
                        if pixel:
                            rects.append(pygame.Rect(attack_rect))
                            print("collide")

if __name__ == '__main__':
    for c in collide_hit['kn4.ob']:
        pprint(c.max)
        print(c)
