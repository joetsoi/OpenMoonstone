from collections import defaultdict
from enum import IntEnum, auto
from pathlib import Path, PureWindowsPath

from extract import grouper
from settings import MOONSTONE_DIR


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
                collide_dict[collide_file].append([])
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
            coordinates = list(grouper(groups, 2))
            assert len(coordinates) == pair_count
            collide_dict[collide_file].append(coordinates)
            state = ParseState.COUNT
    return collide_dict


def load_collision_file(filename):
    file_path = Path(MOONSTONE_DIR) / PureWindowsPath(filename)
    with open(file_path, 'r') as f:
        return parse_collision_file(f)


collide = load_collision_file("COLLIDE.HIT")
