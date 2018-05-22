import copy
import sys
from pprint import pprint

import pygame

import settings
from assets import main_menu
from cli import print_hex_view
from combat.encounter import Encounter


def game_loop(screen):
    encounter = Encounter()

    clock = pygame.time.Clock()
    last_tick = pygame.time.get_ticks()
    background = encounter.lair.draw().convert()
    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()

        now = pygame.time.get_ticks()
        time = now - last_tick
        # if time > 1000 / (18.2065 / 2):
        #if time > 1000 / ((1193182 / 21845) * 2):
        #if time > 1000 / ((1193182 / 21845) * 2):
        #    knights.update()
        #    last_tick = now
        encounter.controller_system.update()
        encounter.state_system.update()
        encounter.movement_system.update()
        encounter.graphics_system.update(background)
        encounter.audio_system.update()
        #collide.active.update()

        image = background.convert()
        y_sorted = pygame.sprite.Group()
        y_sorted.add(sorted(iter(encounter.graphics_system.active), key=lambda s: s.rect.bottom))
        y_sorted.draw(image)


        encounter.collision_system.update()
        #collide.check_collisions()
        encounter.logic_system.update(encounter)
        encounter.blood_system.update(background)  # TODO change background to world component
        #destroy_entites()

        #pygame.draw.rect(
        #    image,
        #    (255, 255, 255),

        #    #pygame.rect.Rect(knight.rect.x, knight.rect.y, 0, 0),
        #    pygame.rect.Rect(knight_1.rect.x, knight_1.rect.y, knight_1.image.get_width(), knight_1.image.get_height()),
        #    1,
        #)
        #print("rects", rects)
        if settings.DEBUG:
            for r in encounter.collision_system.debug_rects:
                pygame.draw.rect(
                    image,
                    (255, 255, 255),
                    r,
                    1,
                )
            encounter.collision_system.debug_rects = []

            pygame.draw.rect(
                image,
                (255, 255, 255),

                #pygame.rect.Rect(knight.rect.x, knight.rect.y, 0, 0),
                pygame.rect.Rect(0, 113, 320, 1),
                1,
            )
        scaled = pygame.transform.scale(
            image,
            (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
        )
        screen.blit(scaled, (0, 0))

        pygame.display.update()
        #clock.tick(settings.FRAME_LIMIT)
        clock.tick(1000 / (1193182 / 21845 * 2))


def menu(screen):
    background = main_menu.draw()
    pygame.image.save(background, 'menu.png')
    image = background.convert()
    alpha = 0
    image.set_alpha(alpha)


    start_tick = pygame.time.get_ticks()
    clock = pygame.time.Clock()
    loop = True
    while loop:
        for event in pygame.event.get():
            if event.type == pygame.KEYDOWN and event.key == pygame.K_SPACE:
                loop = False
                print('hello')
            elif event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()

        now = pygame.time.get_ticks()
        delta = now - start_tick
        fade_in_ms = 274
        if delta > fade_in_ms:
            alpha = 255
        else:
            alpha = int(delta / fade_in_ms * 255)
        image.set_alpha(alpha)
        scaled = pygame.transform.scale(
            image,
            (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
        )
        screen.blit(scaled, (0, 0))
        pygame.display.update()
        clock.tick(1000 / (1193182 / 21845 * 2))


if __name__ == "__main__":
    pygame.mixer.pre_init(16129, -16, 2, 2048)
    pygame.mixer.init()
    pygame.init()
    pygame.display.set_caption("OpenMoonstone")
    screen = pygame.display.set_mode(
        (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
    )

    menu(screen)
    game_loop(screen)
