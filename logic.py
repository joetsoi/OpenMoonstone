from collections import UserList

from attr import attrib, attrs

from collide import Collision
from graphics import set_animation
from state import State
from system import SystemFlag


@attrs(slots=True)
class Logic:
    health = attrib(type=int, default=10)
    weapon_damage = attrib(type=int, default=3)

    def resolve_give_collision(self, defender):
        print('give')

    def resolve_take_collision(self, attacker):
        print('take')


class LogicSystem(UserList):
    flags = SystemFlag.logic + SystemFlag.collision
    def update(self):
        recover_after_attack = []
        take_damage = []
        attackers = [e for e in self.data if (e.collision.has_hit and e.state.value == State.attacking)]
        for attacker in attackers:
            recover_after_attack.append(attacker)
            defender = attacker.collision.has_hit
            take_damage.append(defender)
            defender.logic.health -= attacker.logic.weapon_damage

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
            set_animation(
                animation_name='some',
                frame_number=-1,
                graphics=entity.graphics,
                movement=entity.movement,
                state=entity.state,
            )
            entity.state.value = State.busy
            print(f"{entity.logic.health}")




logic_system = LogicSystem()
