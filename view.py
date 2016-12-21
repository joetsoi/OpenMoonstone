import copy
import os, sys
import pygame
from pygame.locals import *
from extract import extract_palette, grouper
from piv import PivFile
from font import FontFile, draw_string
from cli import print_hex_view
from main import MainExe
import pdb
from struct import unpack, unpack_from


scale_factor = 3


def draw(screen, image_data, palette):
    image = pygame.Surface((320, 200))
    image.fill((255, 255, 255))


    pixel_array = pygame.PixelArray(image)

    for y, line in enumerate(grouper(image_data, 320)):
        for x, pixel in enumerate(line):
            pixel_array[x, y] = palette[pixel]


    del pixel_array
    image = pygame.transform.scale(image, (320 * scale_factor, 200 * scale_factor))
    screen.blit(image, (0, 0))




if __name__ == "__main__":
    if len(sys.argv) != 4:
    #if len(sys.argv) != 3:
        print("Usage: view.arg <filename> <piv file>")
        sys.exit()

    file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           sys.argv[2])
    with open(file_path, 'rb') as f:
        piv = PivFile(f.read())

    file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           sys.argv[1])
    with open(file_path, 'rb') as f:
        font = FontFile(f.read())

    main_exe = MainExe(
        file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               'MAIN.EXE')
    )

    default_palette = extract_palette(main_exe.palette, base=256)
    pixels = copy.deepcopy(piv.pixels)
    piv_palette = copy.deepcopy(piv.palette)
    #piv.palette = default_palette
    #print_hex_view(main_exe.bold_f_char_lookup)

    #print_hex_view(piv.pixels)
    image_number = int(sys.argv[3])

    font.extract_subimage(piv, int(sys.argv[3]), 0, 0)

    # font.extract_subimage(piv, 0x49, 0x5, 0x14)

    # font.extract_subimage(piv, 0x4a, 0x16, 0xb5)
    # font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)

    # font.extract_subimage(piv, 0x45, 0x6e, 0xbe)

    # for string, metadata in main_exe.strings.items():
    #     draw_string(piv, font, string, metadata[2], main_exe)

#    for i in range(6):
#        font.extract_subimage(piv, i, i*20, 0)

    pygame.init()
    screen = pygame.display.set_mode((320 * scale_factor, 200 * scale_factor))

    while True:
        for event in pygame.event.get():
            if event.type == QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT:
                    image_number = (image_number - 1) % font.image_count
                elif event.key == pygame.K_RIGHT:
                    image_number = (image_number + 1) % font.image_count
                elif event.key == pygame.K_UP:
                    piv.palette = copy.deepcopy(piv_palette)
                elif event.key == pygame.K_DOWN:
                    piv.palette == copy.deepcopy(default_palette)
                print(image_number)
                piv.pixels = copy.deepcopy(pixels)
                font.extract_subimage(piv, image_number, 0, 0)

        pygame.display.update()
        pygame.time.wait(250)
        draw(screen, piv.pixels, piv.palette)
