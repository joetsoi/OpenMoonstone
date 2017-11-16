import os

from cmp import CmpFile
from piv import PivFile
from font import FontFile, StringFlag, String
from t import TFile
from screen import ImageLocation, Screen, Lair
from settings import MOONSTONE_DIR
from . import animation


bold_font_char_lookup = (
    69, 62, 69, 66, 67, 68, 69, 70, 69, 69,
    69, 69, 65, 69, 64, 71, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 69, 69, 69, 69,
    69, 69, 69, 0, 1, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 69,
    71, 69, 69, 69, 69, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 69, 69, 69, 69, 48
)


def load_file(file_type, filename):
    file_path = os.path.join(MOONSTONE_DIR, filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return file_type(data)


backgrounds = {
    'ch': load_file(PivFile, 'DISKB\CH.PIV'),
    'wab1': load_file(PivFile, 'DISKB\WAB1.CMP'),

}


scenery_files = {
    'fo1': load_file(CmpFile, 'DISKB\FO1.CMP'),
    'fo2': load_file(CmpFile, 'DISKB\FO2.CMP'),
    'sw1': load_file(CmpFile, 'DISKB\SW1.CMP'),
    'wa1': load_file(CmpFile, 'DISKB\WA1.CMP'),
}

scenery = [
    scenery_files['fo1'],
    scenery_files['fo1'],
    scenery_files['sw1'],
    scenery_files['wa1'],
    scenery_files['fo2'],
]

fonts = {
    'bold': load_file(FontFile, 'DISKA\BOLD.F'),
    'small': load_file(FontFile, 'DISKB\SMALL.FON'),
}

objects = {
    'kn1': load_file(FontFile, 'DISKB\KN1.OB'),
    'kn4': load_file(FontFile, 'DISKB\KN4.OB'),
}

spritesheets = {
    'bold.f': fonts['bold'],
    'kn1.ob': objects['kn1'],
    'kn4.ob': objects['kn4'],
}

terrain = {
    'wa1': load_file(TFile, 'DISKB\WA1.T'),
}

lairs = (
    Lair('wab1', 'wa1'),
)

loading_screen = Screen(
    background='ch',
    text=[
        String(0, 90, "created by", StringFlag.centered + StringFlag.bordered, 'bold'),
        String(0, 105, "Rob Anderson", StringFlag.centered + StringFlag.bordered, 'bold'),
        String(0, 150, "Loading...", StringFlag.centered + StringFlag.bordered, 'bold')
    ],
    images=[
        ImageLocation('bold.f', 73, 5, 20),
        ImageLocation('bold.f', 74, 22, 181),
        ImageLocation('bold.f', 75, 110, 190),    ]
)
