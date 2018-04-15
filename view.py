import copy
import sys
from pprint import pprint

import pygame

import assets
import collide
import graphics
import settings
from assets import lairs, loading_screen
from cli import print_hex_view
from cmp import CmpFile
from collide import Collider, Collision, collision_system
from controller import Controller, controller_system, player_one, player_two
from entity import Entity
from extract import extract_palette
from graphics import Graphic, Move, graphics_system
from logic import Logic, logic_system
from main import MainExe
from movement import Movement, movement_system
from piv import PivFile
from t import TFile

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
    one_up_controller = Controller(player_one)
    movement_1 = Movement((100, 100))
    graphics_1 = Graphic(
        animations=assets.animation.knight,
        position=movement_1.position,
        palette=assets.files.backgrounds[lairs[0].background].palette,
        lair=lair,
        groups=[graphics.active],
    )
    collider_1 = Collision(
        graphics=graphics_1,
        movement=movement_1,
        collider=Collider(assets.animation.knight, assets.collide_hit),
    )
    logic_1 = Logic(graphics_1)

    knight_1 = Entity(
        controller=one_up_controller,
        movement=movement_1,
        graphics=graphics_1,
        collider=collider_1,
        logic=logic_1,
    )

    palette = change_player_colour(
        'blue',
        assets.files.backgrounds[lairs[0].background].extracted_palette,
    )
    two_up_controller = Controller(player_two)
    movement_2 = Movement((200, 150))
    graphics_2 = Graphic(
        animations=assets.animation.knight,
        position=movement_2.position,
        palette=palette,
        lair=lair,
        groups=[graphics.active],
    )
    collider_2 = Collision(
        graphics=graphics_2,
        movement=movement_2,
        collider=Collider(assets.animation.knight, assets.collide_hit),
    )
    logic_2 = Logic(graphics_2)

    knight_2 = Entity(
        controller=two_up_controller,
        movement=movement_2,
        graphics=graphics_2,
        collider=collider_2,
        logic=logic_2,
    )
    if controller_system.flags in knight_1.flags:
        controller_system.append(knight_1)

    if controller_system.flags in knight_2.flags:
        controller_system.append(knight_2)

    if movement_system.flags in knight_1.flags:
        movement_system.append(knight_1)

    if movement_system.flags in knight_2.flags:
        movement_system.append(knight_2)

    if graphics_system.flags in knight_1.flags:
        graphics_system.append(knight_1)

    if graphics_system.flags in knight_2.flags:
        graphics_system.append(knight_2)

    collision_system.extend([collider_1, collider_2])
    logic_system.extend([knight_1.logic, knight_2.logic])
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
        controller_system.update()
        movement_system.update()
        graphics_system.update()
        #collide.active.update()

        collision_system.update()
        #collide.check_collisions()
        logic_system.update()

        image = lair.draw().copy()
        graphics.active.draw(image)

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
