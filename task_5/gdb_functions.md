Functions list in gdb:
- main() @ 0x55555555c1d0
- sanitise_stdfd() @ 0x555555572350
- platform_disable_tracing() @ 0x555555578640
- ssh_get_progname @ 0x55555557c550
- seed_rng @ 0x555555577200
- mktemp_proto @ 0x555555572f70
- unix_listener @ 0x555555573180
- log_init @ 0x55555556dc80
- **pkcs11_init @ 0x55555555f3f0**
- new_socket @ 0x55555555d2f0
- **idtab_init @ 0x55555556faf0** **maybe? YES!**
- ssh_signal @ 0x555555574bf0
- pledge @ 0x55555557c5a0 : takes args despite Ghidra not showing
  - @ 0x555555578610 ? YE
- poll @ 0x55555557f240




Bolded functions are potentially very important for finding id storage