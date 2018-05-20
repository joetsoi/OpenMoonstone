from pathlib import Path, PureWindowsPath

from pygame.mixer import Sound

from resources.cmp import CmpFile
from resources.font import FontFile
from resources.piv import PivFile
from settings import MOONSTONE_DIR
from resources.terrain import TerrainFile

from .collide import parse_collision_file


def load_file(file_type, filename):
    file_path = Path(MOONSTONE_DIR) / PureWindowsPath(filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return file_type(data)


def load_collision_file(filename):
    file_path = Path(MOONSTONE_DIR) / PureWindowsPath(filename)
    with open(file_path, 'r') as f:
        return parse_collision_file(f)


def load_sound(filename):
    file_path = Path(MOONSTONE_DIR) / PureWindowsPath(filename)
    return Sound(str(file_path))


backgrounds = {
    'ch': load_file(PivFile, 'DISKB\CH.PIV'),
    'mindscape': load_file(PivFile, 'DISKA\MINDSCAP'),
    'wab1': load_file(PivFile, 'DISKB\WAB1.CMP'),
}

scenery_files = {
    'fo1': load_file(CmpFile, 'DISKB\FO1.CMP'),
    'fo2': load_file(CmpFile, 'DISKB\FO2.CMP'),
    'sw1': load_file(CmpFile, 'DISKB\SW1.CMP'),
    'wa1': load_file(CmpFile, 'DISKB\WA1.CMP'),
}

fonts = {
    'bold': load_file(FontFile, 'DISKA\BOLD.F'),
    'small': load_file(FontFile, 'DISKB\SMALL.FON'),
}

objects = {
    'sel': load_file(FontFile, 'SEL.CEL'),
    'kn1': load_file(FontFile, 'DISKB\KN1.OB'),
    'kn2': load_file(FontFile, 'DISKB\KN2.OB'),
    'kn3': load_file(FontFile, 'DISKB\KN3.OB'),
    'kn4': load_file(FontFile, 'DISKB\KN4.OB'),
}

terrain = {
    'wa1': load_file(TerrainFile, 'DISKB\WA1.T'),
    'wa2': load_file(TerrainFile, 'DISKB\WA2.T'),
    'wa3': load_file(TerrainFile, 'DISKB\WA3.T'),
}


collide_hit = load_collision_file("COLLIDE.HIT")

sounds = {
    'hit3': 'SAMPLES\\HIT3',
    'grnt3': 'SAMPLES\\GRNT3',
    'kstep': 'SAMPLES\\KSTEP',
    'rjgrunt4': 'SAMPLES\\RJGRUNT4',
    'swish': 'SAMPLES\\SWISH',
    'swordcl': 'SAMPLES\\SWORDCL',
}
