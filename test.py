import os
from struct import iter_unpack
from piv import PivFile, grouper
from font import FontFile, draw_string
from extract import extract_file
from main import MainExe


class TestPivFile(object):
    def setup(self):
        self.file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'MINDSCAP'
        )
        self.mindscape = PivFile(self.file_path)

    def test_extract_piv_file(self):
        extracted = extract_file(self.mindscape.file_length,
                                 self.mindscape.pixel_data)
        with open('mindscap_extract_1.bin', 'rb') as f:
            test_data = f.read()

        assert extracted == test_data

    def test_extract_pixels(self):
        '''The original code would extract the code into video memory into the
        four memory blocks in unchained mode, this tests recreates those blocks
        '''
        block_a = []
        block_b = []
        block_c = []
        block_d = []

        extracted = self.mindscape.extract_pixels()

        for a, b, c, d in grouper(extracted, 4):
            block_a.append(a)
            block_b.append(b)
            block_c.append(c)
            block_d.append(d)

        blocks = block_a + block_b + block_c + block_d
        with open('mindscap_video_mem.bin', 'rb') as f:
            test_data = f.read()

        assert bytearray(blocks) == bytearray(test_data)

    def test_extract_palette(self):
        extracted = self.mindscape.extract_palette()

        with open('mindscap_palette_extract_1.bin', 'rb') as f:
            test_data = f.read()

        assert extracted == [i[0] for i in iter_unpack('<H', test_data)]


class TestLoadingScreen(object):
    def setup(self):
        self.file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'CH.PIV'
        )
        self.background = PivFile(self.file_path)
        bold_f_file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'BOLD.F'
        )
        self.bold_f = FontFile(bold_f_file_path) 

    def test_loading_screen(self):
        main_exe = MainExe(
            file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   'MAIN.EXE')
        )

        self.bold_f.extract_subimage(self.background, 0x49, 0x5, 0x14)
        self.bold_f.extract_subimage(self.background, 0x4a, 0x16, 0xb5)
        self.bold_f.extract_subimage(self.background, 0x4b, 0x6e, 0xbe)
        self.bold_f.extract_subimage(self.background, 0x45, 0x6e, 0xbe)

        for string, metadata in main_exe.strings.items():
            draw_string(self.background, self.bold_f, string, metadata[2], main_exe)

        block_a = []
        block_b = []
        block_c = []
        block_d = []

        extracted = self.background.pixels

        for a, b, c, d in grouper(extracted, 4):
            block_a.append(a)
            block_b.append(b)
            block_c.append(c)
            block_d.append(d)

        blocks = block_a + block_b + block_c + block_d

        with open('memdump.bin', 'rb') as f:
            test_data = f.read()
        print('image ' , len(blocks), 'test_data ', len(test_data))

        assert bytearray(blocks) == bytearray(test_data)
