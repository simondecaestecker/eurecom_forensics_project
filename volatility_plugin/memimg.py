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
        for pid, task, pagedata in data:
            task_space = task.get_process_address_space()

            offset = 0
            if pagedata:
                self.table_header(outfd,
                                  [("Virtual", "[addrpad]"),
                                   ("Physical", "[addrpad]"),
                                   ("Size", "[addr]"),
                                   ("DumpFileOffset", "[addr]"),
                                   ("Data", "[str]")])

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        data = task_space.read(p[0], p[1])

                        output = False
                        if empty_mem in data:
                            output = '0'
                        else:
                            output = '1'

                        self.table_row(outfd, p[0], pa, p[1], offset, output)
                        offset += p[1]
            else:
                outfd.write("Unable to read pages for task.\n")

    @cache.CacheDecorator(lambda self: "tests/memmap/pid={0}/offset={1}".format(self._config.PID, self._config.OFFSET))
    def calculate(self):
        tasks = taskmods.DllList.calculate(self)

        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                task_space = task.get_process_address_space()
                pages = task_space.get_available_pages()
                yield pid, task, pages
