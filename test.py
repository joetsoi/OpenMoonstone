import os
from struct import iter_unpack
from piv import PivFile, grouper
from font import FontFile
from extract import extract_file


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
