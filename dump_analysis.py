#! /usr/bin/env python2

from PIL import Image, ImageFilter
import argparse
import sys
import os.path
import subprocess
from math import ceil


def main ():
    # **********************************************************************
    # * Before doing anything else, check the correctness of the libraries *
    # **********************************************************************


    # *******************
    # * Check arguments *
    # *******************
    parser = argparse.ArgumentParser(description='Create an image from a dump file')
    parser.add_argument("dump_file", metavar='dump_name', help='name of the input dump file')
    parser.add_argument("-k" , "--kernel_offset", metavar="kernel_offset", help="Address of the kernel space limit in hexadecimal")
    parser.add_argument("-s", "--size", help='size of the image in pixels heightxwidth (ex: 500x500)')
    parser.add_argument("-o", "--output", metavar='output_name', type=str, help='name of the output image (by default, same as input dump file)')
    parser.add_argument("-f", "--format", type=str, choices=['png', 'jpg', 'bmp', 'gif'], help="Output format of the image (png by default)")
    args = parser.parse_args()

    #check if provided dump file exists
    if not os.path.isfile(args.dump_file):
        sys.exit("Dumpfile does not exist. Check the path.")

    #check size argument is set. If yes, parse it and verify format.
    if args.size is not None:
        height, width = args.size.split('x')
        if not (height.isdigit() and width.isdigit()):
            sys.exit("Image size argument is not in the correct format.\nCorrect format is 500x500 for example.")
        else:
            height = int(height)
            width = int(width)
            if(height < 100 or width < 100):
                sys.exit("Image size should be 100x100 minimum")
    else:
        width = 500
        height = 500

    #Check if optional output name is set. If not, set a default one.
    if args.output is None:
        args.output = "my_image"

    #check if image format argument is set. if not, assign default one.
    if args.format is None:
        args.format = 'png'

    if args.kernel_offset is None:
        sys.exit("I'm not capable to determine the offset of the kernel...\nPlease specify the address of the kernel offset in hexadecimal using the -k parameter.")

    list_mem = []

    size_max = os.path.getsize(args.dump_file)
    size_max_float = float(size_max)
    page = 0
    nbr_pages = size_max / 0x1000

    while (page < size_max):
        cmd_xxd = 'xxd -a -s '+str(page)+' -l 0x1000 '+args.dump_file+' -'

        p = subprocess.Popen(cmd_xxd, stdout=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        result = out.split('\n')

        if page <= int(args.kernel_offset, 16):  # User space
            if (len(result) == 4):  # Page not used
                list_mem.append("u0")
            else:
                list_mem.append("u1")
        else:                           # Kernel space
            if (len(result) == 4):  # Page not used
                list_mem.append("k0")
            else:
                list_mem.append("k1")

        page += 0x1000

        print(chr(27) + "[2J")
        print '%.2f' % (page / size_max_float * 100) + " %"

    #Create image based on data from dump file
    create_image(list_mem, args.output, height, width, args.format)


    # ************************************
    # * ...                              *
    # ************************************


# Function to create an image based on the input dumpfile
def create_image(list_mem, output_name, height, width, format):
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

if __name__ == "__main__":
    main ()
