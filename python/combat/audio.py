from collections import UserList
from typing import Dict, List, Optional

import pygame
from attr import attrib, attrs

from .state import State
from .system import SystemFlag


def make_sound_list(animations):
    sounds = {}
    for name, animation_definition in animations.items():
        animation_sounds = [None] * len(animation_definition)
        if animation_definition.sounds:
            for frame_sound in animation_definition.sounds:
                animation_sounds[frame_sound.frame] = frame_sound.sound
        sounds[name] = animation_sounds
    return sounds


@attrs(slots=True)
class Audio:
    sounds = attrib(type=Dict[str, List[Optional[str]]], converter=make_sound_list)


class AudioSystem(UserList):
    flags = SystemFlag.ANIMATIONSTATE + SystemFlag.AUDIO

    def __init__(self, initlist=None, assets=None):
        super().__init__(initlist)
        self.assets = assets

    def update(self):
        for entity in self.data:
            audio = entity.audio
            state = entity.state
            animation = audio.sounds.get(state.animation_name)
            if animation:
                sound = audio.sounds[state.animation_name][state.frame_num]
                if sound:
                    self.assets.sounds[sound].play()
