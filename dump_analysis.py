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
    parser.add_argument("-p" , "--profile", metavar="profile", help="Profile used in Volatility")
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

    if args.profile is not None:
        if "Win" in args.profile:
            #python vol.py -f <image_path> --profile=<profile> kdbgscan
            cmd = 'python ../volatility/vol.py -f '+args.dump_file+' --profile='+args.profile+' kdbgscan'

            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            out, err = p.communicate()
            result = out.split('\n')
            for lin in result:
                if "KernelBase" in lin:
                    lin = lin[lin.index(':')+2:]
                    lin = lin[:lin.index('(')-1]
                    args.kernel_offset = lin
                    break
    else:
        if args.kernel_offset is None:
            sys.exit("I'm not capable to determine the offset of the kernel...\nPlease specify the address of the kernel offset in hexadecimal using the -k parameter.")

    list_mem = []
    size_max = 1950*0x1000
    #size_max = os.path.getsize(args.dump_file)
    size_max_float = float(size_max)
    page = 0
    nbr_pages = size_max / 0x1000

    while (page < size_max):
        cmd_xxd = 'xxd -a -s '+str(page)+' -l 0x1000 '+args.dump_file+' -'

        p = subprocess.Popen(cmd_xxd, stdout=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        result = out.split('\n')
        #print hex(page) + " --> " + hex(page + 0x1000 - 1) + " :: ",
        if (len(result) == 4):  # Page not used
            list_mem.append(0)
        else:                   # Page used
            if page <= args.kernel_offset:  # User space
                list_mem.append(1)
            else:                           # Kernel space
                list_mem.append(2)

        page += 0x1000

        print(chr(27) + "[2J")
        print '%.2f' % (page / size_max_float * 100) + " %"
        print(list_mem)
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
    #for every col
    for i in range(size[0]):
        #for every row
        for j in reversed(range(size[1])):
            #set the colour accordingly
            if (elmt >= len(list_mem)):
                pixels[i,j] = (0, 0, 0)
            else:
                if (list_mem[elmt] == 0):    # Page not used
                    pixels[i,j] = (220, 220, 220)
                elif (list_mem[elmt] == 1):  # User space
                    pixels[i,j] = (255, 0, 0)
                elif (list_mem[elmt] == 2):  # Kernel space
                    pixels[i,j] = (0, 255, 0)
            elmt += 1

    img.show()

    img.save('my_image.'+format)

if __name__ == "__main__":
    main ()
