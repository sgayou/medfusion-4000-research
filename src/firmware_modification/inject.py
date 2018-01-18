#!/usr/bin/python3
import argparse
import binascii
import os
import struct
import sys

parser = argparse.ArgumentParser()
parser.add_argument("firmware", help="Firmware file name")
parser.add_argument("code", help="Code to inject into firmware file name")
parser.add_argument("output", help="Injected firmware output file name.")
parser.add_argument('--address',type=lambda x: int(x,0),
                    default=0x31005510, help="Address to overwrite in firmware. (Default: 0x31005510)")
args = parser.parse_args()

with open(args.firmware, 'rb') as file:
    firmware_buf = bytearray(file.read())

with open(args.code, 'rb') as file:
    code_buf = bytearray(file.read())

# Sanity check address. Subtract the base offset and add the 0x80 byte header.
target_address = (args.address - 0x30000000) + 0x80
if target_address < 0 or target_address > len(firmware_buf) - len(code_buf):
    print("ERROR: Address out of range.")
    sys.exit(1)

# Inject our code.
for idx, byte in enumerate(code_buf):
    firmware_buf[target_address + idx] = byte

# Recompute Header

with open(args.output, 'wb') as file:
    file.write(firmware_buf)
