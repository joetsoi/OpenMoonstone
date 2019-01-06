from collections import UserList

from attr import attrib, attrs

from .blood import create_knight_blood_stain
from .graphics import set_animation
from .state import Attack, State
from .system import SystemFlag


@attrs(slots=True)
class Logic:
    health = attrib(type=int, default=10)
    weapon_damage = attrib(type=int, default=3)
    dodged = attrib(type=bool, default=False)


knight_counter = {
    Attack.swing: Attack.block,
    Attack.back: Attack.block,
    Attack.chop: Attack.dodge,
    Attack.thrust: Attack.dodge,
}


class LogicSystem(UserList):
    flags = SystemFlag.LOGIC + SystemFlag.COLLISION + SystemFlag.ANIMATIONSTATE

    def update(self, encounter):
        recover_after_attack = []
        take_damage = []
        attackers = [
            entity
            for entity in self.data
            if (entity.collision.has_hit and entity.state.value == State.attacking)
        ]
        for attacker in attackers:
            defender = attacker.collision.has_hit
            if defender.state.value == State.attacking:
                defender_action = Attack[defender.state.animation_name]
                attacker_action = Attack[attacker.state.animation_name]
                if defender_action == knight_counter[attacker_action]:
                    if defender_action == Attack.dodge:
                        if not defender.logic.dodged:
                            defender.logic.dodged = True
                            continue
                    else:
                        recover_after_attack.append(attacker)
                        continue

            take_damage.append(defender)
            defender.logic.health -= attacker.logic.weapon_damage
            attacker.collision.has_hit = None

        for entity in recover_after_attack:
            set_animation(
                animation_name="recovery",
                frame_number=-1,
                graphics=entity.graphics,
                movement=entity.movement,
                state=entity.state,
            )
            entity.state.value = State.busy

        for entity in take_damage:
            if defender.logic.health <= 0:
                set_animation(
                    animation_name="death",
                    frame_number=-1,
                    graphics=entity.graphics,
                    movement=entity.movement,
                    state=entity.state,
                )
                entity.state.value = State.loop_once
            else:
                set_animation(
                    animation_name="some",
                    frame_number=-1,
                    graphics=entity.graphics,
                    movement=entity.movement,
                    state=entity.state,
                )
                entity.state.value = State.busy
                print(f"{entity.logic.health}")
                blood_stain = create_knight_blood_stain(
                    "some",
                    entity.graphics.palette,
                    entity.movement.facing,
                    entity.movement.position,
                )
                encounter.register_entity(blood_stain)
