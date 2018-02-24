import copy
import sys
from pprint import pprint

import pygame

from cli import print_hex_view
from extract import extract_palette
from main import MainExe
from piv import PivFile
from cmp import CmpFile

from t import TFile
from assets import loading_screen, lairs
import assets
import collide
import settings
from graphics import Graphic, graphics_system, Move
from input import input_system, player_one, player_two, Input
from movement import movement_system, Movement

from entity import Entity


controls = {
    pygame.K_LEFT: Move.LEFT,
    pygame.K_RIGHT: Move.RIGHT,
}


def change_player_colour(colour: str, palette: list):
    colours = {
        'blue': [0xa, 0x7, 0x4],
        'orange': [0xf80, 0xc50, 0xa30],
        'green': [0x8c6, 0x593, 0x251],
        'red': [0xf22, 0xb22, 0x700],
        'black': [0x206, 0x103, 1],
    }
    palette = copy.deepcopy(palette)
    # palette[0xc // 2:0xc // 2 + 2] = colours[colour]
    palette[6:8] = colours[colour]
    palette = extract_palette(palette, base=256)
    return PivFile.make_palette(palette)


def game_loop(screen):
    lair = lairs[0]
    one_up_input = Input(player_one)
    movement_1 = Movement(one_up_input, (100, 100))
    graphics_1 = Graphic(
        one_up_input,
        movement_1,
        assets.animation.knight,
        assets.files.backgrounds[lairs[0].background].palette,
        lair,
        groups=[collide.active],
    )

    knight_1 = Entity(
        input=one_up_input,
        movement=movement_1,
        graphics=graphics_1,
    )

    palette = change_player_colour(
        'blue',
        assets.files.backgrounds[lairs[0].background].extracted_palette,
    )
    two_up_input = Input(player_two)
    movement_2 = Movement(two_up_input, (200, 150))
    graphics_2 = Graphic(
        two_up_input,
        movement_2,
        assets.animation.knight,
        palette,
        lair,
        groups=[collide.active],
    )

    knight_2 = Entity(
        input=two_up_input,
        movement=movement_2,
        graphics=graphics_2
    )
    input_system.extend([knight_1.input, knight_2.input])
    movement_system.extend([knight_1.movement, knight_2.movement])
    graphics_system.extend([knight_1.graphics, knight_2.graphics])
    clock = pygame.time.Clock()
    last_tick = pygame.time.get_ticks()
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
        input_system.update()
        movement_system.update()
        graphics_system.update()
        #collide.active.update()

        collide.check_collision()

        image = lair.draw().copy()
        collide.active.draw(image)

        #pygame.draw.rect(
        #    image,
        #    (255, 255, 255),

        #    #pygame.rect.Rect(knight.rect.x, knight.rect.y, 0, 0),
        #    pygame.rect.Rect(knight_1.rect.x, knight_1.rect.y, knight_1.image.get_width(), knight_1.image.get_height()),
        #    1,
        #)
        #print("rects", rects)
        freeze = False
        for r in collide.rects:
            freeze = True

            pygame.draw.rect(
                image,
                (255, 255, 255),
                r,
                1,
            )
        collide.rects = []

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
        if freeze:
            test = 1
        #clock.tick(settings.FRAME_LIMIT)
        clock.tick(1000 / (1193182 / 21845 * 2))


if __name__ == "__main__":
    pygame.init()
    pygame.display.set_caption("OpenMoonstone")
    screen = pygame.display.set_mode(
        (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
    )
    game_loop(screen)
