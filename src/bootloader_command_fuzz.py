#!/usr/bin/python3
import serial
import itertools
import string
import time

prompt_str = b'\r\n> \n> '
invalid_str = b'Invalid Command\r\n> \n> '

with serial.Serial('/dev/ttyUSB0', 115200, timeout=None) as ser:
    ser.write(b'\r\n')
    ser.read(len(prompt_str))

    for cmdlen in range(1, 9):
        print("Testing command length: " + str(cmdlen))
        for cmd in itertools.product(string.ascii_lowercase, repeat=cmdlen):
            print(''.join(cmd) + "\r", end='')
            cmd_str = (''.join(cmd) + "\r\n").encode('utf8')
            ser.write(cmd_str)
            out = ser.read(len(cmd_str) + len(invalid_str))
            if "Invalid Command" not in out.decode('utf8'):
                print("Command found: " + ''.join(cmd))
                time.sleep(2)
                ser.reset_input_buffer()
                ser.write(b'\r\n')
                ser.read(len(prompt_str))