from collections import UserList

from attr import attrib, attrs

from collide import Collision
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

            frame, x = defender.graphics.get_frame(
                'some',
                0,
                defender.movement.position,
                defender.movement.direction
            )
            defender.graphics.set_frame_image(
                'some',
                0,
                defender.movement,
                x,
                defender.movement.position.y + frame.rect.y,
                frame.rect.width,
                frame.rect.height,
                frame.surface,
            )


            print(f"{defender.logic.health}")



logic_system = LogicSystem()
