#define printf ((int (*)())0x300B1CF0)

void _start() {
  printf("Dumping bl:\n");

  for (int j = 0x0; j < 0x80000; j += 0x1) {
    printf("%02x ", *((unsigned char *)j));
  }

  printf("\nImage dumped.");
}
