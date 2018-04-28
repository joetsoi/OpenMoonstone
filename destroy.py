from blood import blood_system
from collide import collision_system
from controller import controller_system
from graphics import graphics_system
from logic import logic_system
from movement import movement_system
from state import state_system, State
from system import SystemFlag


def destroy_entites():
    systems = {
        SystemFlag.blood: blood_system,
        SystemFlag.controller: controller_system,
        SystemFlag.state: state_system,
        SystemFlag.movement: movement_system,
        SystemFlag.graphics: graphics_system,
        SystemFlag.collision: collision_system,
        SystemFlag.logic: logic_system,
    }
    entities = [e for e in state_system if e.state.value == State.destroy]
    for entity in entities:
        for flag, system in systems.items():
            if flag in entity.flags:
                system.remove(entity)
