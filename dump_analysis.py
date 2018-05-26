#! /usr/bin/env python2

from PIL import Image, ImageFilter
import argparse


def main ():
    # **********************************************************************
    # * Before doing anything else, check the correctness of the libraries *
    # **********************************************************************


    # *************************************
    # * Check arguments and read datafile *
    # *************************************
    parser = argparse.ArgumentParser(description='Create an image from a dump file')
    parser.add_argument("dumpfile", metavar='filename', help='name of the dump file')
    parser.add_argument("width", type=int, help='width of the image in pixels')
    parser.add_argument("height", type=int, help='height of the image in pixels')
    parser.add_argument("-f", "--format", type=str, choices=['png', 'jpg', 'bmp'], help="Output format of the image (png by default)")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    args = parser.parse_args()


    # ************************************
    # * Compute and print average timing *
    # ************************************

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
