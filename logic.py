from collections import UserList

from attr import attrs, attrib

from collide import Collision



@attrs(slots=True)
class Logic:
    collision = attrib(type=Collision)
    health = attrib(type=int, default=10)
    weapon_damage = attrib(type=int, default=3)

    def resolve_give_collision(self, defender):
        print('give')

    def resolve_take_collision(self, attacker):
        print('take')


class LogicSystem(UserList):
    def update(self):
        attackers = [l for l in self.data if l.collision.has_hit]
        for attacker in attackers:
            pass
            defender = attacker.has_hit
            



logic_system = LogicSystem()
