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


def change_player_colour(colour: str, palette: list):
    colours = {
        'blue': [0xa, 0x7, 0x4],
        'orange': [0xf80, 0xc50, 0xa30],
        'green': [0x8c6, 0x593, 0x251],
        'red': [0xf22, 0xb22, 0x700],
        'black': [0x206, 0x103, 1],
    }
    palette = copy.deepcopy(palette)
    old_palette = extract_palette(palette, base=256)
    # palette[0xc // 2:0xc // 2 + 2] = colours[colour]
    palette[6:8] = colours[colour]
    new_palette = extract_palette(palette, base=256)

    # This is the blood colour, which is an incorrect orange in new_pallete
    # investigate in ida if this gets overrriden later
    new_palette[15] = old_palette[15]
    return PivFile.make_palette(new_palette)


def create_player(colour: str, x: int, y: int, lair, control_map):
    controller = Controller(control_map)
    movement = Movement((x, y))

    palette = change_player_colour(
        colour,
        assets.files.backgrounds[lair.background].extracted_palette,
    )
    graphic = Graphic(
        animations=assets.animation.knight,
        position=movement.position,
        palette=palette,
        lair=lair,
        groups=[graphics_system.active],
    )
    collider = Collision(
        collider=Collider(assets.animation.knight, assets.collide_hit),
    )
    logic = Logic()

    knight = Entity(
        controller=controller,
        movement=movement,
        graphics=graphic,
        collision=collider,
        logic=logic,
        state=AnimationState(),
    )

    register_entity_with_systems(knight)
    return knight


def register_entity_with_systems(entity):
    systems = {
        SystemFlag.controller: controller_system,
        SystemFlag.state: state_system,
        SystemFlag.movement: movement_system,
        SystemFlag.graphics: graphics_system,
        SystemFlag.collision: collision_system,
        SystemFlag.logic: logic_system,
    }

    for flag, system in systems.items():
        if flag in entity.flags:
            system.append(entity)


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
    pygame.init()
    pygame.display.set_caption("OpenMoonstone")
    screen = pygame.display.set_mode(
        (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
    )
    game_loop(screen)
