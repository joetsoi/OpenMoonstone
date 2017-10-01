import pygame
import piv


class CmpFile(piv.PivFile):
    image_height = 25
    image_width = 32

    def __init__(self, file_data):
        super().__init__(file_data)
        self.surface = self.make_surface()

    def get_image_data(self, image_number):
        pass

    def get_image(self, image_number):
        max_x_image = 320 // self.image_width

        x = (image_number % max_x_image) * self.image_width
        y = (image_number // max_x_image) * self.image_height
        rect = pygame.Rect(x, y, self.image_width, self.image_height)
        print(rect)
        return self.surface.subsurface(rect)

    def make_palette(self):
        palette = super().make_palette()
        palette[0] = pygame.Color(0, 0, 0, 0)
        return palette