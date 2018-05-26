#! /usr/bin/env python2

from PIL import Image, ImageFilter
import argparse
import sys
import os.path


def main ():
    # **********************************************************************
    # * Before doing anything else, check the correctness of the libraries *
    # **********************************************************************


    # *******************
    # * Check arguments *
    # *******************
    parser = argparse.ArgumentParser(description='Create an image from a dump file')
    parser.add_argument("dump_file", metavar='dump_name', help='name of the input dump file')
    parser.add_argument("-s", "--size", help='size of the image in pixels heightxwidth (ex: 500x500)')
    parser.add_argument("-o", "--output", metavar='output_name', type=str, help='name of the output image (by default, same as input dump file)')
    parser.add_argument("-f", "--format", type=str, choices=['png', 'jpg', 'bmp', 'gif'], help="Output format of the image (png by default)")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
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

    #Create image based on data from dump file
    create_image(args.dump_file, args.output, height, width, args.format)


    # ************************************
    # * ...                              *
    # ************************************


# Function to create an image based on the input dumpfile
def create_image(dumpfile, output_name, height, width, format):
    #create a new white image
    img = Image.new('RGB', (width,height), "white")

    #create the pixel map
    pixels = img.load()

    #get the size of the image
    size = img.size

    #for every col
    for i in range(size[0]):
        #for every row
        for j in range(size[1]):
            #set the colour accordingly
            pixels[i,j] = (i, j, 100)

    img.save('my_image.'+format)


# Open dumpfile <name> and store its content in global variables
# <ct> and <t>.
def read_dumpfile (name, n):
    global ct, t

    if not isinstance (n, int) or n < 0:
        raise ValueError('Invalid maximum number of traces: ' + str(n))

    try:
        f = open (str(name), 'rb')
    except IOError:
        raise ValueError("cannot open file " + name)
    else:
        try:
            ct = []
            t = []
            for _ in xrange (n):
                a, b = f.readline ().split ()
                ct.append (int(a, 16))
                t.append (float(b))
        except (EnvironmentError, ValueError):
            raise ValueError("cannot read dumpfile")
        finally:
            f.close ()


if __name__ == "__main__":
    main ()
