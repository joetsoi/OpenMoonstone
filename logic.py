from collections import UserList

from attr import attrs, attrib

from graphics import Graphic



@attrs(slots=True)
class Logic:
    health = attrib(type=int, default=10)
    weapon_damage = attrib(type=int, default=3)

    def resolve_give_collision(self, defender):
        print('give')

    def resolve_take_collision(self, attacker):
        print('take')


class LogicSystem(UserList):
    def update(self):
        for logic in self.data:
            pass
            #if logic.graphic.has_hit:
            #    logic.resolve_give_collision(logic.graphic.has_hit)
            #    #defender = logic.graphic.has_hit
            #    import ipdb; ipdb.set_trace()
            #    defender.resolve_take_collision(logic.graphic)


logic_system = LogicSystem()
