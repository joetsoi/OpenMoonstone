from collections import UserList

from attr import attrib, attrs

from collide import Collision
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

            damage_animation = 'some'
            frame, x = defender.graphics.get_frame(
                damage_animation,
                0,
                defender.movement.position,
                defender.movement.facing
            )
            defender.graphics.set_frame_image(
                damage_animation,
                0,
                defender.movement,
                x,
                defender.movement.position.y + frame.rect.y,
                frame.rect.width,
                frame.rect.height,
                frame.surface,
            )
            animation = defender.graphics.animations[damage_animation,
                                                    defender.movement.facing]
            defender.state.animation_name = damage_animation
            defender.state.animation_len = len(animation.order)
            defender.state.frame_num = 0
            defender.state.value = State.busy


            print(f"{defender.logic.health}")



logic_system = LogicSystem()
