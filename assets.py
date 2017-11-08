import os

from cmp import CmpFile
from piv import PivFile
from font import FontFile, StringFlag, String
from t import TFile
from screen import ImageLocation, Screen, Lair
from settings import MOONSTONE_DIR


bold_font_char_lookup = (
    69, 62, 69, 66, 67, 68, 69, 70, 69, 69, 69, 69, 65, 69, 64, 71, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 69, 69, 69, 69, 69, 69, 69, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    69, 71, 69, 69, 69, 69, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 69, 69, 69, 69, 48
)


def load_piv(filename):
    file_path = os.path.join(MOONSTONE_DIR, filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return PivFile(data)


def load_font(filename):
    file_path = os.path.join(MOONSTONE_DIR, filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return FontFile(data)


def load_cmp(filename):
    file_path = os.path.join(MOONSTONE_DIR, filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return CmpFile(data)


def load_t(filename):
    file_path = os.path.join(MOONSTONE_DIR, filename)
    with open(file_path, 'rb') as f:
        data = f.read()
    return TFile(data)


backgrounds = {
    'ch': load_piv('DISKB\CH.PIV'),
    'wab1': load_piv('DISKB\WAB1.CMP')
}


scenery_files = {
    'fo1': load_cmp('DISKB\FO1.CMP'),
    'fo2': load_cmp('DISKB\FO2.CMP'),
    'sw1': load_cmp('DISKB\SW1.CMP'),
    'wa1': load_cmp('DISKB\WA1.CMP'),
}

scenery = [
    scenery_files['fo1'],
    scenery_files['fo1'],
    scenery_files['sw1'],
    scenery_files['wa1'],
    scenery_files['fo2'],
]

fonts = {
    'bold': load_font('DISKA\BOLD.F'),
    'small': load_font('DISKB\SMALL.FON'),
}

spritesheets = {
    'bold.f': fonts['bold'],
}

terrain = {
    'wa1': load_t('DISKB\WA1.T'),
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
        ImageLocation('bold.f', 75, 110, 190),
    ]
)
