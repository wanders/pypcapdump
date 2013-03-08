#
# Author: Anders Waldenborg <anders@0x63.nu>
# Copyright: Copyright (c) 2013, Anders Waldenborg
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Except as contained in this notice, the name(s) of the above copyright
# holders shall not be used in advertising or otherwise to promote the
# sale, use or other dealings in this Software without prior written
# authorization.


import ctypes


DLT_EN10MB = 1

lib = ctypes.CDLL("libpcap.so")

class pcap_t(ctypes.Structure):
    pass

class pcap_dumper_t(ctypes.Structure):
    pass

class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long),
                ("tv_usec", ctypes.c_long)]

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval),
                ("caplen", ctypes.c_int),
                ("len", ctypes.c_int)]

lib.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
lib.pcap_open_dead.restype = ctypes.POINTER(pcap_t)
lib.pcap_close.argtypes = [ctypes.POINTER(pcap_t)]
lib.pcap_close.restype = None

lib.pcap_dump_open.argtypes = [ctypes.POINTER(pcap_t), ctypes.c_char_p]
lib.pcap_dump_open.restype = ctypes.POINTER(pcap_dumper_t)

lib.pcap_dump.argtypes = [ctypes.POINTER(pcap_dumper_t), ctypes.POINTER(pcap_pkthdr), ctypes.c_char_p]
lib.pcap_dump.restype = None

lib.pcap_dump_close.argtypes = [ctypes.POINTER(pcap_dumper_t)]
lib.pcap_dump_close.restype = None


def is_null_ptr(p):
    return ctypes.cast(p, ctypes.c_void_p).value is None


class PcapDumper:
    def __init__(self, path, dlt=DLT_EN10MB):
        self.lib = lib # need to hold a reference to it so it isn't collected at shutdown (before __del__ is run)
        self.pcap = None
        self.pcapdump = None

        pcap = self.lib.pcap_open_dead(dlt, 4096)
        if is_null_ptr(pcap):
            raise ValueError("Couldn't create pcap_t")
        pcapdump = self.lib.pcap_dump_open(pcap, path)
        if is_null_ptr(pcapdump):
            raise ValueError("Couldn't create pcap_dumper_t")

        self.pcap = pcap
        self.pcapdump = pcapdump

    def __del__(self):
        if self.pcapdump is not None:
            self.lib.pcap_dump_close(self.pcapdump)
        if self.pcap is not None:
            self.lib.pcap_close(self.pcap)

    def dump(self, ts, data):
        secs = int(ts)
        usec = int(1000000*(ts - secs))
        hdr=pcap_pkthdr((secs, usec), len(data), len(data))
        lib.pcap_dump(self.pcapdump, ctypes.byref(hdr), data)


if __name__ == '__main__':
    # really simple example
    import sys
    import time
    data = ("\xaa\x00\x04\x00\x69\x04\xaa\x00\x04\x00\x1d\x04"
            "\x90\x00\x00\x00\x02\x00\xaa\x00\x04\x00\x1d\x04"
            "\x01\x00\x01\x00\x55\x55\x55\x55\x55\x55\x55\x55"
            "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
            "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
            "\x55\x55\x55\x55\x55\x55\x55\x55")
    d = PcapDumper(sys.argv[1])
    d.dump(time.time(), data)
