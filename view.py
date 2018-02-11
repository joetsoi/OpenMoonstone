import copy
import os
import sys
from pprint import pprint

import pygame

from cli import print_hex_view
from extract import extract_palette
from font import FontFile#, draw_string
from main import MainExe
from piv import PivFile
from cmp import CmpFile

from t import TFile
from assets import loading_screen, lairs
import assets
import collide
import settings
from input import input_system, player_one, player_two, Input

from entity import Entity, Move


#def draw(screen, image_data, palette):
#    image = pygame.Surface((320, 200))
#    image.fill((255, 255, 255))

    #pixel_array = pygame.PixelArray(image)

    #for y, line in enumerate(grouper(image_data, 320)):
    #    for x, pixel in enumerate(line):
    #        try:
    #            pixel_array[x, y] = palette[pixel]
    #        except TypeError:
    #            pass

    #del pixel_array
    #image = pygame.transform.scale(image,
    #                              (320 * scale_factor, 200 * scale_factor))
    #screen.blit(image, (0, 0))
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
    knight_1 = Entity(
        pygame.Rect(100, 100, 0, 0),
        assets.animation.knight,
        assets.files.backgrounds[lairs[0].background].palette,
        input=Input(player_one),
        lair=lair,
        groups=[collide.active]
    )
    palette = change_player_colour(
        'blue',
        assets.files.backgrounds[lairs[0].background].extracted_palette,
    )
    knight_2 = Entity(
        pygame.Rect(200, 150, 0, 0),
        assets.animation.knight,
        palette=palette,
        input=Input(player_two),
        lair=lair,
        groups=[collide.active]
    )
    input_system.add(knight_1.input, knight_2.input)
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
        collide.active.update()

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
