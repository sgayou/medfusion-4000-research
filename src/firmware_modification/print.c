#define printf 0x300B1CF0 

void _start() { ((int (*)())printf)("Code injected!"); }
