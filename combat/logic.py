from collections import UserList

from attr import attrib, attrs

from .blood import create_knight_blood_stain
from .collide import Collision
from .graphics import set_animation
from .state import State
from .system import SystemFlag


@attrs(slots=True)
class Logic:
    health = attrib(type=int, default=10)
    weapon_damage = attrib(type=int, default=3)

    def resolve_give_collision(self, defender):
        print('give')

    def resolve_take_collision(self, attacker):
        print('take')


class LogicSystem(UserList):
    flags = SystemFlag.LOGIC + SystemFlag.COLLISION
    def update(self, encounter):
        recover_after_attack = []
        take_damage = []
        attackers = [e for e in self.data if (e.collision.has_hit and e.state.value == State.attacking)]
        for attacker in attackers:
            recover_after_attack.append(attacker)
            defender = attacker.collision.has_hit
            take_damage.append(defender)
            defender.logic.health -= attacker.logic.weapon_damage
            attacker.collision.has_hit = None

        for entity in recover_after_attack:
            set_animation(
                animation_name='recovery',
                frame_number=-1,
                graphics=entity.graphics,
                movement=entity.movement,
                state=entity.state,

            )
            entity.state.value = State.busy

        for entity in take_damage:
            if defender.logic.health <= 0:
                set_animation(
                    animation_name='death',
                    frame_number=-1,
                    graphics=entity.graphics,
                    movement=entity.movement,
                    state=entity.state,
                )
                entity.state.value = State.loop_once
            else:
                set_animation(
                    animation_name='some',
                    frame_number=-1,
                    graphics=entity.graphics,
                    movement=entity.movement,
                    state=entity.state,
                )
                entity.state.value = State.busy
                print(f"{entity.logic.health}")
                blood_stain = create_knight_blood_stain(
                    'some',
                    entity.graphics.palette,
                    entity.movement.facing,
                    entity.movement.position,
                )
                encounter.register_entity(blood_stain)
