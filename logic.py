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
        attackers = [e for e in self.data if e.collision.has_hit]
        for attacker in attackers:
            defender = attacker.collision.has_hit
            defender.logic.health -= attacker.logic.weapon_damage

            set_animation(
                animation_name='some',
                graphics=defender.graphics,
                movement=defender.movement,
                state=defender.state,
            )
            defender.state.value = State.busy

            print(f"{defender.logic.health}")


logic_system = LogicSystem()
