import copy
import os
import sys

import pygame

from cli import print_hex_view
from extract import extract_palette, grouper
from font import FontFile#, draw_string
from main import MainExe
from piv import PivFile
from cmp import CmpFile

from t import TFile
from assets import loading_screen, lairs
import assets
import settings

from sprite import Entity, make_frame#, Move


#def draw(screen, image_data, palette):
#    image = pygame.Surface((320, 200))
#    image.fill((255, 255, 255))

    #pixel_array = pygame.PixelArray(image)

    #for y, line in enumerate(grouper(image_data, 320)):
    #    for x, pixel in enumerate(line):
    #        try:
    #            pixel_array[x, y] = palette[pixel]
    #        except TypeError:
    #            pass

    #del pixel_array
    #image = pygame.transform.scale(image,
    #                              (320 * scale_factor, 200 * scale_factor))
    #screen.blit(image, (0, 0))


def game_loop(screen):
    knights = pygame.sprite.Group()
    knight = Entity(pygame.Rect(0, 0, 0, 0), assets.animation.knight,
                    assets.files.backgrounds[lairs[0].background].palette, [knights])
    lair = lairs[0].draw()
    clock = pygame.time.Clock()
    last_tick = pygame.time.get_ticks()
    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT:
                    pass
                    #knight.move(Move.LEFT)
                elif event.key == pygame.K_RIGHT:
                    pass
                    #knight.move(Move.RIGHT)
                    #knights.update()
                
        now = pygame.time.get_ticks()
        time = now - last_tick
        if time > 1000 / 18.2065 * 2:
            knights.update()
            last_tick = now

        image = lair.copy()
        knights.draw(image)
        scaled = pygame.transform.scale(
            image,
            (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
        )
        screen.blit(scaled, (0, 0))

        pygame.display.update()
        clock.tick(settings.FRAME_LIMIT)


if __name__ == "__main__":
    # if len(sys.argv) != 3:
    #if len(sys.argv) != 4:
    #    print("Usage: view.arg <filename> <piv file>")
    #    sys.exit()

    pygame.init()
    screen = pygame.display.set_mode((320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR))

    #file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
    #                         sys.argv[2])
    #with open(file_path, 'rb') as f:
    #    data = f.read()
    #    piv = PivFile(data)


    #file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
    #                         sys.argv[1])
    #with open(file_path, 'rb') as f:
    #    font = FontFile(f.read(), piv)

    #main_exe = MainExe(
    #    file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
    #                           'MAIN.EXE')
    #)

    #default_palette = extract_palette(main_exe.palette, base=256)
    #pixels = copy.deepcopy(piv.pixels)
    #piv_palette = copy.deepcopy(piv.extracted_palette)

    #
    # piv_palette[0xc // 2] = 0x8c6
    # piv_palette[(0xc + 2) // 2] = 0x593
    # piv_palette[(0xc + 4) // 2] = 0x251
    #
    # piv_palette[0x12 // 2] = 0xa
    # piv_palette[(0x12 + 2) // 2] = 0x7
    # piv_palette[(0x12 + 4) // 2] = 0x4
    #
    # piv_palette[0x12 // 2] = 0x206
    # piv_palette[(0x12 + 2) // 2] = 0x103
    # piv_palette[(0x12 + 4) // 2] = 0x1


    #piv.pixels = copy.deepcopy(pixels)
    #piv.palette = default_palette
    #print_hex_view(piv_palette)
    #piv.palette = extract_palette(piv_palette, base=256)
    #print_hex_view(piv.pixels[:0x200:4])
    #import pdb; pdb.set_trace()
    # print_hex_view(main_exe.bold_f_char_lookup)

    # print_hex_view(piv.pixels)
    #image_number = int(sys.argv[3])



    #subsurf = font.extract_subimage(piv, 0x49, 0x5, 0x14)
    #print_hex_view(piv.pixels)
    #print("hello")
    #font.extract_subimage(piv, 0x49, 0x0, 0x14)

    #font.extract_subimage(piv, 0x4a, 0x16, 0xb5)
    #font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)

    #font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)



    #print("world")
#    for i in range(6):
#        font.extract_subimage(piv, i, i*20, 0)
#     font.extract_subimage(piv, 3, 30, 0)
#     font.extract_subimage(piv, 5, 30+3, 30)
#     font.extract_subimage(piv, 7, 30+3+23, 60)
#     font.extract_subimage(piv, 9, 25+3+23+4, 90)
#     font.extract_subimage(piv, 3, 25 + 3 + 23 + 4+25, 120)




    #for string, metadata in main_exe.strings.items():
    #   draw_string(assets.fonts['bold'], string, metadata[2], main_exe)
    frame_number = 0

    game_loop(screen)
    #
    # while True:
    #     for event in pygame.event.get():
    #         if event.type == pygame.QUIT:
    #             pygame.quit()
    #             sys.exit()
    #         elif event.type == pygame.KEYDOWN:
    #             if event.key == pygame.K_LEFT:
    #                 pass
    #             elif event.key == pygame.K_RIGHT:
    #                 knights.update()
                #elif event.key == pygame.K_UP:
                #    piv.palette = copy.deepcopy(piv_palette)
                #elif event.key == pygame.K_DOWN:
                #    piv.palette == copy.deepcopy(default_palette)
                #print(image_number)
        # mouse = pygame.mouse.get_pos()
        #font.extract_subimage(piv, image_number, *mouse)
        #font.extract_subimage(piv, image_number, 0, 0)

        #image = piv.make_surface()

        #image = pygame.transform.scale(image,
        #                               (320 * scale_factor, 200 * scale_factor))
        #screen.blit(image, (0, 0))


        #image.blit(font.images[0x49].surface, (5, 20))
        #image.blit(font.images[0x4a].surface, (0x16, 0xb5))
        #image.blit(font.images[0x4b].surface, (0x6e, 0xbe))
        #for string, metadata in main_exe.strings.items():
        #    draw_string(piv, font, string, metadata[2], main_exe)
        # image = lairs[0].draw()
        # image = loading_screen.draw()
        # image.blit(image, (0, 0))

        #frame = Frame(assets.animation.knight['walk'][frame_number], assets.backgrounds[lairs[0].background].palette)
        #frame, rect = make_frame(assets.animation.knight['walk'][frame_number], assets.backgrounds[lairs[0].background].palette)
        #image.blit(frame, (0, 0))

        # knights.draw(image)
        #
        # image = pygame.transform.scale(
        #     image,
        #     (320 * settings.SCALE_FACTOR, 200 * settings.SCALE_FACTOR)
        # )
        # screen.blit(image, (0, 0))
        #
        #
        #
        # pygame.display.update()
        # pygame.time.sleep(17)
        #




        ##
        #pygame.display.update()
        #pygame.time.wait(100)
        #draw(screen, piv.pixels, piv.palette)
