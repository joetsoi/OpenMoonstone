from collections import defaultdict, UserList
from enum import IntEnum, auto
from pathlib import Path, PureWindowsPath

from extract import grouper
from settings import MOONSTONE_DIR


class Colliders(UserList):
    def __init__(self, data=None):
        super().__init__(data)
        self.last_len = 0
        self._max = (None, None)

    @property
    def max(self):
        if len(self.data) != self.last_len:
            self._max = (
                max((i[0] for i in self.data), default=None),
                max((i[1] for i in self.data), default=None),
            )
        return self._max


class ParseState(IntEnum):
    FILENAME = auto()
    COUNT = auto()
    PADDING = auto()
    COORDINATES = auto()


def parse_collision_file(collide_data):
    collide_dict = defaultdict(list)
    state = ParseState.FILENAME
    pair_count = None
    for line in collide_data:
        if state == ParseState.FILENAME:
            collide_file = line.strip().lower()
            state = ParseState.COUNT

        elif state == ParseState.COUNT:
            pair_count = int(line)
            if pair_count == 0:
                collide_dict[collide_file].append(Colliders())
            elif pair_count == 99:
                state = ParseState.FILENAME
            else:
                state = ParseState.PADDING

        elif state == ParseState.PADDING:
            state = ParseState.COORDINATES

        elif state == ParseState.COORDINATES:
            # convert from list of str to list of ints
            groups = (int(''.join(g)) for g in grouper(line.strip(), 3))
            # group them into x y pairs
            coordinates = Colliders(grouper(groups, 2))
            assert len(coordinates) == pair_count
            collide_dict[collide_file].append(coordinates)
            state = ParseState.COUNT
    collide_dict.default_factory = None
    return collide_dict
