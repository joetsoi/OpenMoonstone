from typing import Dict

from assets import files
from assets.animation import AnimationDefinition


class Manager:
   def __init__(self, entity_definitions):
       self.sounds = {}
       for definition in entity_definitions:
           self.add_entity(definition)

   def add_entity(self, definition: Dict[str, AnimationDefinition]):
       sound_files = set()
       for animation_definition in definition.values():
           if animation_definition.sounds:
               for frame_sound in animation_definition.sounds:
                   sound_files.add(frame_sound.sound)
       self.load_sounds(sound_files)

   def load_sounds(self, sound_names):
       for sound_name in sound_names:
           if sound_name not in self.sounds:
               sound_file = files.sounds[sound_name]
               self.sounds[sound_name] = files.load_sound(sound_file)
