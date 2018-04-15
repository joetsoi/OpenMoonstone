import copy
import os
import sys

import pygame

import assets
import settings
from cli import print_hex_view
from cmp import CmpFile
from extract import extract_palette, grouper
from font import FontFile  # , draw_string
from main import MainExe
from piv import PivFile
from t import TFile

scale_factor = 3


def draw(screen, image_data, palette):
    image = pygame.Surface((320, 200))
    image.fill((255, 255, 255))

    pixel_array = pygame.PixelArray(image)

    for y, line in enumerate(grouper(image_data, 320)):
        for x, pixel in enumerate(line):
            try:
                pixel_array[x, y] = palette[pixel]
            except TypeError:
                pass

    del pixel_array
    image = pygame.transform.scale(image,
                                   (320 * scale_factor, 200 * scale_factor))
    screen.blit(image, (0, 0))


if __name__ == "__main__":
    # if len(sys.argv) != 3:
    if len(sys.argv) != 5:
        print("Usage: view.arg <filename> <piv file>")
        sys.exit()

    pygame.init()
    screen = pygame.display.set_mode((320 * scale_factor, 200 * scale_factor))

    file_path = os.path.join(settings.MOONSTONE_DIR,
                             sys.argv[2])
    with open(file_path, 'rb') as f:
        data = f.read()
        piv = PivFile(data)


    file_path = os.path.join(settings.MOONSTONE_DIR,
                             sys.argv[1])
    with open(file_path, 'rb') as f:
        #font = FontFile(f.read())
        cmp = CmpFile(f.read())

    file_path = os.path.join(settings.MOONSTONE_DIR,
                             sys.argv[4])
    with open(file_path, 'rb') as f:
        #font = FontFile(f.read())
        positions = TFile(f.read())

    main_exe = MainExe(
        file_path=os.path.join(settings.MOONSTONE_DIR,
                               'MAIN.EXE')
    )

    default_palette = extract_palette(main_exe.palette, base=256)
    pixels = copy.deepcopy(piv.pixels)
    piv_palette = copy.deepcopy(piv.extracted_palette)
    piv_palette[0xc // 2] = 0x8c6
    piv_palette[(0xc + 2) // 2] = 0x593
    piv_palette[(0xc + 4) // 2] = 0x251

    piv_palette[0x12 // 2] = 0xa
    piv_palette[(0x12 + 2) // 2] = 0x7
    piv_palette[(0x12 + 4) // 2] = 0x4

    piv_palette[0x12 // 2] = 0x206
    piv_palette[(0x12 + 2) // 2] = 0x103
    piv_palette[(0x12 + 4) // 2] = 0x1
    #piv.palette = default_palette
    #print_hex_view(piv_palette)
    piv.palette = extract_palette(piv_palette, base=256)
    print_hex_view(piv.pixels[:0x200:4])
    #import pdb; pdb.set_trace()
    # print_hex_view(main_exe.bold_f_char_lookup)

    # print_hex_view(piv.pixels)
    image_number = int(sys.argv[3])


    #font.extract_subimage(piv, int(sys.argv[3]), 0, 0)

    #font.extract_subimage(piv, 0x49, 0x5, 0x14)

    #font.extract_subimage(piv, 0x4a, 0x16, 0xb5)
    #font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)

    # font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)

    #for string, metadata in main_exe.strings.items():
    #    draw_string(piv, font, string, metadata[2], main_exe)

#    for i in range(6):
#        font.extract_subimage(piv, i, i*20, 0)



    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT:
                    image_number = (image_number - 1) % font.image_count
                elif event.key == pygame.K_RIGHT:
                    image_number = (image_number + 1) % font.image_count
                #elif event.key == pygame.K_UP:
                #    piv.palette = copy.deepcopy(piv_palette)
                #elif event.key == pygame.K_DOWN:
                #    piv.palette == copy.deepcopy(default_palette)
                print(image_number)
        piv.pixels = copy.deepcopy(pixels)
        #mouse = pygame.mouse.get_pos()
        #font.extract_subimage(piv, image_number, *mouse)

        #font.extract_subimage(piv, image_number, 0, 0)


        image = piv.make_surface()
        image.blit(image, (0, 0))
        for pos in positions.positions:
            cmp = assets.scenery[pos.cmp_file]
            image.blit(cmp.get_image(pos.image_number), (pos.x, pos.y))

        image = pygame.transform.scale(image,
                                       (320 * scale_factor, 200 * scale_factor))
        screen.blit(image, (0, 0))
        pygame.display.update()
        pygame.time.wait(100)
        #draw(screen, piv.pixels, piv.palette)
