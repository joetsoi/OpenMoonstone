#import copy
#import os
#import sys

#import pygame

#from cli import print_hex_view
#from cmp import CmpFile
#from extract import extract_palette, grouper
#from font import FontFile, draw_string
#from main import MainExe
#from piv import PivFile
#from terrain import TerrainFile

#scale_factor = 4


#def draw(screen, image_data, palette):
#    image = pygame.Surface((320, 200))
#    image.fill((255, 255, 255))

#    pixel_array = pygame.PixelArray(image)

#    for y, line in enumerate(grouper(image_data, 320)):
#        for x, pixel in enumerate(line):
#            try:
#                pixel_array[x, y] = palette[pixel]
#            except TypeError:
#                pass

#    del pixel_array
#    image = pygame.transform.scale(image,
#                                   (320 * scale_factor, 200 * scale_factor))
#    screen.blit(image, (0, 0))


#if __name__ == "__main__":
#    if len(sys.argv) != 2:
#    #if len(sys.argv) != 5:
#        print("Usage: view.arg <filename> <piv file>")
#        sys.exit()

#    pygame.init()
#    screen = pygame.display.set_mode((320 * scale_factor, 200 * scale_factor))

#    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
#                             sys.argv[1])
#    with open(file_path, 'rb') as f:
#        data = f.read()
#        piv = PivFile(data)



#    main_exe = MainExe(
#        file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
#                               'MAIN.EXE')
#    )

#    default_palette = extract_palette(main_exe.palette, base=256)
#    pixels = copy.deepcopy(piv.pixels)
#    #import pdb; pdb.set_trace()
#    # print_hex_view(main_exe.bold_f_char_lookup)

#    # print_hex_view(piv.pixels)


#    #font.extract_subimage(piv, int(sys.argv[3]), 0, 0)

#    #font.extract_subimage(piv, 0x49, 0x5, 0x14)

#    #font.extract_subimage(piv, 0x4a, 0x16, 0xb5)
#    #font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)

#    # font.extract_subimage(piv, 0x4b, 0x6e, 0xbe)

#    #for string, metadata in main_exe.strings.items():
#    #    draw_string(piv, font, string, metadata[2], main_exe)

##    for i in range(6):
##        font.extract_subimage(piv, i, i*20, 0)



#    while True:
#        for event in pygame.event.get():
#            if event.type == pygame.QUIT:
#                pygame.quit()
#                sys.exit()
#        piv.pixels = copy.deepcopy(pixels)
#        #mouse = pygame.mouse.get_pos()
#        #font.extract_subimage(piv, image_number, *mouse)

#        #font.extract_subimage(piv, image_number, 0, 0)


#        image = piv.make_surface()
#        image.blit(image, (0, 0))
#        image = pygame.transform.scale(image,
#                                       (320 * scale_factor, 200 * scale_factor))
#        screen.blit(image, (0, 0))
#        pygame.display.update()
#        pygame.time.wait(100)
#        #draw(screen, piv.pixels, piv.palette)

from assets.files import load_file
from resources.piv import PivFile
piv = load_file(PivFile, 'DISKA\MINDSCAP')
print()
#print([i for i in piv.extracted])
#print(piv.pixels)
#print(piv.palette)
