all:
	m68k-linux-gnu-gcc code.c -mcpu=5282 -nostartfiles -Wl,-Ttext=0x31005510 -Wall
	m68k-linux-gnu-objcopy --only-section=.text --only-section=.rodata --output-target binary a.out code.bin
	m68k-linux-gnu-objdump -d a.out
	./inject.py medfusion4000-1.1.2.bin code.bin mod.bin
clean:
	rm a.out code.bin mod.bin
