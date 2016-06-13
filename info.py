from collections import defaultdict
import os, sys
from font import FontFile

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: info.py <file>')
        sys.exit()

    file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           sys.argv[1])
    with open(file_path, 'rb') as f:
        font = FontFile(f.read())
    print('Total images: {}'.format(font.image_count))
    image_types = defaultdict(int)
    for i, header in enumerate(font.headers):
        image_types[header.blit_type] += 1
        #print('blit type: {}\twidth: {}\theight: {}'.format(
        #    header.blit_type,
        #    header.width,
        #    header.height,
        #))

    for k, v in image_types.items():
        print('blit type: {}'.format(k))
                                                        
