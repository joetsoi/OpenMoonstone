from attr import attrib, attrs

import assets
from font import StringFlag, pixel_to_surface


@attrs
class Screen:
    background = attrib()
    text = attrib()
    images = attrib()

    def draw(self):
        surface = assets.backgrounds[self.background].make_surface()
        for string in self.text:
            self.draw_string(surface, string)
        for image in self.images:
            self.draw_image(surface, image)
        return surface

    def draw_image(self, background, image_meta):
        spritesheet = assets.spritesheets[image_meta.spritesheet]
        image = spritesheet.images[image_meta.image_number]
        image_surface = pixel_to_surface(
            image.width, image.height, image.pixels, assets.backgrounds[self.background].palette)
        background.blit(image_surface, (image_meta.x, image_meta.y))

    def draw_string(self, image, string):
        font = assets.fonts[string.font]
        char_numbers = []
        char_widths = []
        ords = []
        for char in string.text:
            char_number = assets.bold_font_char_lookup[ord(char) - 0x20]
            ords.append(ord(char) - 0x20)
            char_image = font.headers[char_number]  # TODO don't use font.headers
            if StringFlag.bordered & string.flags:
                width = char_image.width - 3
            else:
                width = char_image.width
            char_numbers.append(char_number)
            char_widths.append(width)
        print(f"new {string.text}", ords, char_numbers)

        string_width = sum(char_widths)
        if StringFlag.centered & string.flags:
            center = int((image.get_width() - string_width) / 2)
            x = center
        else:
            x = string.x

        for i, w in zip(char_numbers, char_widths):
            char = font.images[i]
            char_surface = pixel_to_surface(
                char.width, char.height, char.pixels, assets.backgrounds[self.background].palette)
            image.blit(char_surface, (x, string.y))
            x += w

        return image


@attrs
class Lair:
    background = attrib()
    terrain = attrib()

    @property
    def terrain_object(self):
        return assets.files.terrain[self.terrain]

    def draw(self):
        background = assets.files.backgrounds[self.background]
        surface = background.make_surface()

        terrain = assets.files.terrain[self.terrain]
        for t in terrain.positions:
            cmp = assets.scenery[t.cmp_file]
            surface.blit(cmp.get_image(t.image_number), (t.x, t.y))
        return surface


@attrs
class ImageLocation:
    spritesheet = attrib()
    image_number = attrib()
    x = attrib()
    y = attrib()
