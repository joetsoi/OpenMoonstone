import os, sys
import pygame
from pygame.locals import *
from piv import PivFile, grouper


def print_hex_view(data):
    for i in range(0, len(data), 0x10):
        print(hex(i), ":", end=' ')
        for j in range(0, 0x10):
            if i+j < len(data):
                print(hex(data[i+j]), end=' ')
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: view.arg <filename>")
        sys.exit()

    mindscape = PivFile(
        file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                               sys.argv[1])
    )

    pygame.init()
    screen = pygame.display.set_mode((320 * 4, 200 * 4))

    image = pygame.Surface((320, 200))
    image.fill((255, 255, 255))

    pixel_array = pygame.PixelArray(image)

    for x, line in enumerate(grouper(mindscape.pixels, 320)):
        for y, pixel in enumerate(line):
            pixel_array[y][x] = mindscape.palette[pixel]

    del pixel_array
    image = pygame.transform.scale(image, (320 * 4, 200 * 4))
    screen.blit(image, (0, 0))
    while True:
        for event in pygame.event.get():
            if event.type == QUIT:
                pygame.quit()
                sys.exit()
            pygame.display.update()
            pygame.time.wait(100)
