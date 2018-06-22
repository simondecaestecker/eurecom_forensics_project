import os, re
import volatility.plugins.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.win32 as win32
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.cache as cache
import volatility.plugins.taskmods as taskmods
import volatility.plugins.kdbgscan as kdbgscan
import volatility.commands as commands
import time
import sys
from PIL import Image, ImageFilter
from math import ceil

# Inherit from files just for the config options (__init__)
class MemMapTest(taskmods.DllList):
    """Print the memory map test"""
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("width", short_option = 'W',
                          default = 500, type = 'int',
                          help = "width of the image in pixels")

        config.add_option("kernel_offset", short_option = 'K',
                          default = None, help = "Address of the kernel space limit in hexadecimal")

        config.add_option("output_name", short_option = 'O',
                          default = 'my_image', help = "Name of the image")

        config.add_option("output_format", short_option = 'F', choices=['png', 'jpg', 'bmp', 'gif'],
                          default = 'png', help = "Output format of the image (png by default)")

        if self._config.kernel_offset is None:
            sys.exit("\nI'm not capable to determine the offset of the kernel...\n\nPlease specify the address of the kernel offset in hexadecimal using the -K parameter.\n")



    def unified_output(self, data):
        return TreeGrid([("Process", str),
                       ("PID", int),
                       ("Virtual", Address),
                       ("Physical", Address),
                       ("Size", Address),
                       ("DumpFileOffset", Address),
                       ("Data", String)],
                        self.generator(data))

    def generator(self, data):
        for pid, task, pagedata in data:
            task_space = task.get_process_address_space()
            proc = "{0}".format(task.ImageFileName)
            offset = 0
            if pagedata:
                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        data = task_space.read(p[0], p[1])
                        if data != None:
                            yield (0, [proc, int(pid), Address(p[0]), Address(pa), Address(p[1]), Address(offset), data])
                            offset += p[1]

    def render_text(self, outfd, data):
        empty_mem = 4096*'?'

        image_width = self._config.width
        kernel_offset = self._config.kernel_offset
        output_name = self._config.output_name
        image_format = self._config.output_format

        outfd.write('\nimage_width:'+str(image_width)+'\n')
        outfd.write('kernel:'+str(kernel_offset)+'\n')
        outfd.write('output_name:'+str(output_name)+'\n')
        outfd.write('image_format:'+str(image_format)+'\n\n')



        first = True

        list_pages = set()

        for pid, task, pagedata in data:
            task_space = task.get_process_address_space()

            offset = 0
            if pagedata:
                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        data = task_space.read(p[0], p[1])

                        output = False
                        if p[0] <= int(kernel_offset, 16):  # User space
                            if empty_mem in data:  # Page not used
                                output = "u0"
                            else:
                                output = "u1"
                        else:                           # Kernel space
                            if empty_mem in data:  # Page not used
                                output = "k0"
                            else:
                                output = "k1"

                        list_pages.add((p[0], output))
                        offset += p[1]

            else:
                outfd.write("Unable to read pages for task.\n")

        if len(list_pages) >  0:
            list_pages_sorted = sorted(list_pages, key=lambda x: x[0])
            list_mem = [x[1] for x in list_pages_sorted]

            #Create image based on data from dump file
            create_image(list_mem, output_name, image_width, image_format)


    @cache.CacheDecorator(lambda self: "tests/memmap/pid={0}/offset={1}".format(self._config.PID, self._config.OFFSET))
    def calculate(self):
        tasks = taskmods.DllList.calculate(self)

        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                task_space = task.get_process_address_space()
                pages = task_space.get_available_pages()
                yield pid, task, pages

# Function to create an image based on the input dumpfile
def create_image(list_mem, output_name, width, format):
    height = int( ceil( len(list_mem) / float(width) ) )

    #create a new white image
    img = Image.new('RGB', (width,height), "white")

    #create the pixel map
    pixels = img.load()

    #get the size of the image
    size = img.size

    elmt = 0
    #for every row
    for j in reversed(range(size[1])):
        #for every col
        for i in range(size[0]):
            #set the colour accordingly
            if (elmt >= len(list_mem)):
                pixels[i,j] = (0, 0, 0)
            else:
                if (list_mem[elmt] == "u0"):    # User space page not used
                    pixels[i,j] = (170, 170, 170)
                elif (list_mem[elmt] == "u1"):  # User space page used
                    pixels[i,j] = (0, 0, 150)
                elif (list_mem[elmt] == "k0"):  # Kernel space page not used
                    pixels[i,j] = (240, 210, 110)
                elif (list_mem[elmt] == "k1"):  # Kernel space page used
                    pixels[i,j] = (200, 150, 0)
            elmt += 1

    img.show()

    img.save(output_name + "." +format)
