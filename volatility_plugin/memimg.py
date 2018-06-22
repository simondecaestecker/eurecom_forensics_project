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
import time
from PIL import Image, ImageFilter
from math import ceil

# Inherit from files just for the config options (__init__)
class MemMapTest(taskmods.DllList):
    """Print the memory map test"""

    def unified_output(self, data):
        return TreeGrid([("Process", str),
                       ("PID", int),
                       ("Virtual", Address),
                       ("Physical", Address),
                       ("Size", Address),
                       ("DumpFileOffset", Address),
                       ("Data", str)],
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
                            output = False
                            if empty_mem in data:
                                output = '0'
                            else:
                                output = '1'
                            yield (0, [proc, int(pid), Address(p[0]), Address(pa), Address(p[1]), Address(offset), output])
                            offset += p[1]

    def render_text(self, outfd, data):
        empty_mem = 4096*'?'

        first = True

        list_pages = set()

        for pid, task, pagedata in data:
            task_space = task.get_process_address_space()

            offset = 0
            if pagedata:
                '''self.table_header(outfd,
                                  [("Virtual", "[addrpad]"),
                                   ("Physical", "[addrpad]"),
                                   ("Size", "[addr]"),
                                   ("DumpFileOffset", "[addr]"),
                                   ("Data", "[str]")])'''

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        data = task_space.read(p[0], p[1])

                        output = False
                        if empty_mem in data:
                            output = "u0"
                        else:
                            output = "u1"

                        #self.table_row(outfd, p[0], pa, p[1], offset, output)
                        list_pages.add((p[0], output))
                        offset += p[1]

            else:
                outfd.write("Unable to read pages for task.\n")

        if len(list_pages) >  0:
            list_pages_sorted = sorted(list_pages, key=lambda x: x[0])
            list_mem = [x[1] for x in list_pages_sorted]

            #Create image based on data from dump file
            #create_image(list_mem, args.output, width, args.format)
            #create_image(list_mem, "out.jpg", 500, "jpg")


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

    img.save('my_image.'+format)
