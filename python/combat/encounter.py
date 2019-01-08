import copy

import assets
from assets.manager import Manager
from combat import graphics
from resources.extract import extract_palette
from resources.piv import PivFile

from .ai_controller import AiController, AiControllerSystem
from .audio import Audio, AudioSystem
from .blood import BloodSystem
from .collide import Collider, Collision, CollisionSystem
from .controller import Controller, ControllerSystem, player_one, player_two
from .entity import Entity
from .graphics import Graphics, GraphicsSystem
from .logic import Logic, LogicSystem
from .movement import Movement, MovementSystem
from .state import AnimationState, AnimationStateSystem
from .system import SystemFlag


def change_player_colour(colour: str, palette: list):
    # todo: consider moving this so combat never imports resources
    colours = {
        'blue': [0xa, 0x7, 0x4],
        'orange': [0xf80, 0xc50, 0xa30],
        'green': [0x8c6, 0x593, 0x251],
        'red': [0xf22, 0xb22, 0x700],
        'black': [0x206, 0x103, 1],
        # 'blue': [0xc, 0x9, 0x6],
        # 'orange': [0xfa0, 0xe70, 0xc50],
        # 'red': [0xd00, 0x900, 0x500],
        # 'green': [0xae8, 0x6b5, 0x473],
        # 'black': [0x408, 0x405, 3],
    }
    palette = copy.deepcopy(palette)
    old_palette = extract_palette(palette, base=256)
    # palette[0xc // 2:0xc // 2 + 2] = colours[colour]
    palette[6:9] = colours[colour]
    new_palette = extract_palette(palette, base=256)
    print(palette, new_palette)

    # This is the blood colour, which is an incorrect orange in new_pallete
    # investigate in ida if this gets overrriden later
    #new_palette[15] = old_palette[15]
    return PivFile.make_palette(new_palette)


def create_player(colour: str, x: int, y: int, lair, control_map, sprite_groups):
    controller = Controller(control_map)
    movement = Movement((x, y))

    palette = change_player_colour(
        colour,
        assets.files.backgrounds[lair.background].extracted_palette,
    )
    graphic = Graphics(
        animations=assets.animation.knight,
        position=movement.position,
        palette=palette,
        lair=lair,
        groups=sprite_groups,
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
        audio=Audio(sounds=assets.animation.knight),
    )

    return knight


def create_black_knight(colour: str, x: int, y: int, lair, opponent, sprite_groups):
    controller = AiController(opponent, y_range=4, close_range=80, long_range=100)
    movement = Movement((x, y))

    palette = change_player_colour(
        colour,
        assets.files.backgrounds[lair.background].extracted_palette,
    )
    graphic = Graphics(
        animations=assets.animation.knight,
        position=movement.position,
        palette=palette,
        lair=lair,
        groups=sprite_groups,
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
        audio=Audio(sounds=assets.animation.knight),
    )

    return knight


class Encounter:
    def __init__(self):
        self.asset_manager = Manager([assets.animation.knight])
        self.lair = assets.lairs[0]

        self.ai_controller_system = AiControllerSystem()
        self.audio_system = AudioSystem(assets=self.asset_manager)
        self.blood_system = BloodSystem()
        self.collision_system = CollisionSystem()
        self.controller_system = ControllerSystem()
        self.graphics_system = GraphicsSystem()
        self.logic_system = LogicSystem()
        self.movement_system = MovementSystem()
        self.state_system = AnimationStateSystem()


        blue = create_player('blue', 100, 100, self.lair, player_one, [self.graphics_system.active])
        self.register_entity(blue)
        red = create_black_knight('red', 200, 150, self.lair, blue, [self.graphics_system.active])
        self.register_entity(red)

    def register_entity(self, entity):
        systems = {
            SystemFlag.AICONTROLLER: self.ai_controller_system,
            SystemFlag.AUDIO: self.audio_system,
            SystemFlag.BLOODSTAIN: self.blood_system,
            SystemFlag.CONTROLLER: self.controller_system,
            SystemFlag.ANIMATIONSTATE: self.state_system,
            SystemFlag.MOVEMENT: self.movement_system,
            SystemFlag.GRAPHICS: self.graphics_system,
            SystemFlag.COLLISION: self.collision_system,
            SystemFlag.LOGIC: self.logic_system,
        }

        for flag, system in systems.items():
            if flag in entity.flags:
                system.append(entity)

    def destroy_entites(self):
        systems = {
            SystemFlag.AICONTROLLER: self.ai_controller_system,
            SystemFlag.AUDIO: self.audio_system,
            SystemFlag.BLOODSTAIN: self.blood_system,
            SystemFlag.CONTROLLER: self.controller_system,
            SystemFlag.ANIMATIONSTATE: self.state_system,
            SystemFlag.MOVEMENT: self.movement_system,
            SystemFlag.GRAPHICS: self.graphics_system,
            SystemFlag.COLLISION: self.collision_system,
            SystemFlag.LOGIC: self.logic_system,
        }
        entities = [e for e in state_system if e.state.value == State.destroy]
        for entity in entities:
            for flag, system in systems.items():
                if flag in entity.flags:
                    system.remove(entity)
