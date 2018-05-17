import copy
import sys
from pprint import pprint

import pygame

import assets
import collide
import graphics
import settings
from assets import lairs, loading_screen
from assets.manager import Manager
from cli import print_hex_view
from cmp import CmpFile
from collide import Collider, Collision
from controller import Controller, player_one, player_two
#from destroy import destroy_entites
from encounter import Encounter
from entity import Entity
from extract import extract_palette
from graphics import Graphic, Move
from logic import Logic
from main import MainExe
from movement import Movement
from state import AnimationState
from system import SystemFlag
from piv import PivFile
from terrain import TerrainFile

controls = {
    pygame.K_LEFT: Move.LEFT,
    pygame.K_RIGHT: Move.RIGHT,
}


def game_loop(screen):
    encounter = Encounter()

    clock = pygame.time.Clock()
    last_tick = pygame.time.get_ticks()
    background = encounter.lair.draw().copy()
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

        image = background.copy()
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


if __name__ == "__main__":
    pygame.mixer.pre_init(16129, -16, 2, 2048)
    pygame.mixer.init()
    pygame.init()
    pygame.display.set_caption("OpenMoonstone")
    screen = pygame.display.set_mode(
        (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
    )
    game_loop(screen)
