import os
from struct import iter_unpack

import pytest

from extract import extract_file, grouper
from font import FontFile, draw_string
from main import MainExe
from piv import PivFile
from sprite import SpriteSheetFile


def read_file(file_name, file_type):
    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             file_name)

    with open(file_path, 'rb') as f:
        file_data = f.read()
    return file_type(file_data)


@pytest.fixture
def mindscape():
    return read_file('MINDSCAP', PivFile)


class TestPivFile(object):
    def test_extract_piv_file(self, mindscape):
        extracted = extract_file(mindscape.file_length, mindscape.pixel_data)
        with open('mindscap_extract_1.bin', 'rb') as f:
            test_data = f.read()

        assert extracted == test_data

    def test_extract_pixels(self, mindscape):
        '''The original code would extract the code into video memory into the
        four memory blocks in unchained mode, this tests recreates those blocks
        '''
        block_a = []
        block_b = []
        block_c = []
        block_d = []

        extracted = mindscape.extract_pixels()

        for a, b, c, d in grouper(extracted, 4):
            block_a.append(a)
            block_b.append(b)
            block_c.append(c)
            block_d.append(d)

        blocks = block_a + block_b + block_c + block_d
        with open('mindscap_video_mem.bin', 'rb') as f:
            test_data = f.read()

        assert bytes(blocks) == test_data

    def test_extract_palette(self, mindscape):
        extracted = mindscape.extract_palette()

        with open('mindscap_palette_extract_1.bin', 'rb') as f:
            test_data = f.read()

        assert extracted == [i[0] for i in iter_unpack('<H', test_data)]


@pytest.fixture
def loading_screen():
    return read_file('CH.PIV', PivFile)


@pytest.fixture
def bold_font():
    return read_file('BOLD.F', FontFile)


@pytest.fixture
def main_exe():
    return MainExe(file_path=os.path.join(
        os.path.dirname(os.path.realpath(__file__)), 'MAIN.EXE'))


class TestLoadingScreen(object):
    def test_loading_screen(self, loading_screen, bold_font, main_exe):
        bold_font.extract_subimage(loading_screen, 0x49, 0x5, 0x14)
        bold_font.extract_subimage(loading_screen, 0x4a, 0x16, 0xb5)
        bold_font.extract_subimage(loading_screen, 0x4b, 0x6e, 0xbe)
        bold_font.extract_subimage(loading_screen, 0x45, 0x6e, 0xbe)

        for string, metadata in main_exe.strings.items():
            draw_string(loading_screen, bold_font, string, metadata[2],
                        main_exe)

        with open('loading_screen.bin', 'rb') as f:
            test_data = f.read()

        assert bytes(loading_screen.pixels) == test_data


def test_sprite():
    test = read_file('BOLD.F', SpriteSheetFile)
    import pdb; pdb.set_trace()

