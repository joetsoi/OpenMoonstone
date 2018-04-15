from collections import namedtuple
from struct import unpack, unpack_from

Segment = namedtuple('Segment', 'offset length')
ViewportDimension = namedtuple('ViewportDimension', 'right left')


class MainExe(object):
    def __init__(self, file_path):
        data_segment = Segment(0x138a0, 0xf460)

        with open(file_path, 'rb') as f:
            f.seek(data_segment.offset)
            data_segment_data = f.read(data_segment.length)

        self.bold_f_char_lookup = unpack(
            '>96B',
            data_segment_data[0x8006:0x8006 + (128 - 32)]
        )

        self.screen_dimensions = ViewportDimension(*unpack(
            '<2H',
            data_segment_data[0x8002:0x8006]
        ))

        self.strings = {
            'created by': unpack(
                '<5H',
                data_segment_data[0x8DCC:0x8DCC + 10] #should back 10
            ),
            'Loading...': unpack(
                '<5H',
                data_segment_data[0x8de0:0x8de0 + 10]
            ),
            'Rob Anderson': unpack(
                '<5H',
                data_segment_data[0x8dd6:0x8dd6 + 10]
            ),
        }

        self.palette = unpack(
            '<32H', data_segment_data[0x892:0x892 + 0x40]
        )
