from font import StringFlag, String
from screen import ImageLocation, Screen, Lair
from . import animation, files  # noqa


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


scenery = [
    files.scenery_files['fo1'],
    files.scenery_files['fo1'],
    files.scenery_files['sw1'],
    files.scenery_files['wa1'],
    files.scenery_files['fo2'],
]

spritesheets = {
    'bold.f': files.fonts['bold'],
    'kn1.ob': files.objects['kn1'],
    'kn3.ob': files.objects['kn3'],
    'kn4.ob': files.objects['kn4'],
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
    ],
)
