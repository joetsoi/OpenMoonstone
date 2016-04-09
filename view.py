import os, sys
import pygame
from pygame.locals import *
from piv import PivFile, grouper
from font import FontFile
from cli import print_hex_view


scale_factor = 3


def draw(screen, image_data, palette):
    image = pygame.Surface((320, 200))
    image.fill((255, 255, 255))


    pixel_array = pygame.PixelArray(image)

    for x, line in enumerate(grouper(image_data, 320)):
        for y, pixel in enumerate(line):
            pixel_array[y][x] = palette[pixel]

    del pixel_array
    image = pygame.transform.scale(image, (320 * scale_factor, 200 * scale_factor))
    screen.blit(image, (0, 0))
    while True:
        for event in pygame.event.get():
            if event.type == QUIT:
                pygame.quit()
                sys.exit()
            pygame.display.update()
            pygame.time.wait(100)



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: view.arg <filename> <piv file>")
        sys.exit()

    piv = PivFile(
        file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               sys.argv[2])
    )

    font = FontFile(
        file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               sys.argv[1])
    )

    #print_hex_view(piv.pixels)
    font.extract_header(piv, 0x49, 5, 0x14)
    font.extract_header(piv, 0x4a, 0x16, 0xb5)
    font.extract_header(piv, 0x4b, 0x6e, 0xbe)
        

    pygame.init()
    screen = pygame.display.set_mode((320 * scale_factor, 200 * scale_factor))

    draw(screen, piv.pixels, piv.palette)
