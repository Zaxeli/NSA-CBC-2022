# Task 5 - Core Dumped - (Reverse Engineering, Cryptography) Points: 500


**Description:**

The FBI knew who that was, and got a warrant to seize their laptop. It looks like they had an encrypted file, which may be of use to your investigation.

We believe that the attacker may have been clever and used the same RSA key that they use for SSH to encrypt the file. We asked the FBI to take a core dump of `ssh-agent` that was running on the attacker's computer.

Extract the attacker's private key from the core dump, and use it to decrypt the file.

Hint: if you have the private key in PEM format, you should be able to decrypt the file with the command `openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc`

**Downloads:**

- Core dump of ssh-agent from the attacker's computer (core)
- ssh-agent binary from the attacker's computer. The computer was running Ubuntu 20.04. (ssh-agent)
- Encrypted data file from the attacker's computer (data.enc)

**Prompt:**

Enter the token value extracted from the decrypted file.

## Solution

> This might be the hardest challenge in the whole competition because of how deep it takes you into reverse engineering the binary. The only other that might be a contender is Task 8.


There are 8 phases to solving this:
<!-- 1. Understanding theory of ssh-agent
2. Reverse engineering
3. Looking for functions
4. Finding `idtab`
5. Finding where key is stored
6. Parsing sshkey elements: `shielded_private`, etc
7. Decrypting shielded private key
8. Understanding blob structure and formatting private key
9. Solved! -->

1. ssh-agent theory
2. Reverse engineering 
   1. Initial inspections
   2. Looking in source code
3. Looking for functions
4. Looking for `idtab` and shielded private key
5. Decrypting the shielded private key
6. Parsing the decrypted private key blob
7. RSA key as .pem
8. Decrypt `data.enc`

### ssh-agent theory

The first thing to do is understand what role ssh-agent plays and how it stores and uses private keys.

When I was researching, I found this resource: http://www.unixwiz.net/techtips/ssh-agent-forwarding.html. It has a very good explanation of what exactly the purpose and role of ssh-agent is in ssh (Go read, if you haven't). The way that ssh-agent supports ssh is that it keeps loads the private keys into memory once when the user starts it. Then, whenever the user needs to make a connection to a remote host, the authentication is forwarded to the ssh-agent which then uses the private key to produce a response for the authentication challenge. It also helps with forwarding where if a user connects to a host and then further connects from there to another host using ssh, the authentication challenge is forwarded all the way back to the original user's host where the agent produces a response and then gets forwarded back to the end host which sent the challenge.
> I highly recommend reading the article.

So, the way that the ssh-agent stores the private keys is only in memory and after the user has unlocked it once at the beginning using a passphrase. Fortunately, this means that getting a coredump of a running ssh-agent binary with the private key loaded in memory would allow us to extract it from the coredump. Later we'll see that the binary keeps these keys in memory in encrypted form, but it's possible to get around that.

Other resources:
- https://stackoverflow.com/questions/2976496/how-to-extract-private-keys-from-an-ssh-agent
- http://www.unixwiz.net/techtips/ssh-agent-forwarding.html
- https://www.netspi.com/blog/technical/network-penetration-testing/stealing-unencrypted-ssh-agent-keys-from-memory/
- https://github.com/NetSPI/sshkey-grab/blob/75f1028a762936d004ae9a9bcd9fb51d9b4e1d99/parse_mem.py#L37

### Reverse Engineering

In order to reverse engineer the binary and see how it is working, we need to use pwndbg. I initially had problems getting it to work with the dump and binary provided, but after reinstalling pwndbg, it worked. This is *far* better than using stock gdb.

Keep in mind that pretty everything now onwards can fall under Reverse Engineering.

#### Initial inspections

Let's load the binary in gdb with the core dump. To load the binary with the coredump:
```
$ sudo gdb ssh-agent --core=core
```

Observations from just loading in gdb:
1. The `rip` is at an invalid address: 
```
──────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────
Invalid address 0x7f8c72ae3967
```
2. Looking at `vmmap` to see how the memory is laid out:
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x5585d287b000     0x5585d2881000 r--p     6000 0      /usr/bin/ssh-agent
    0x5585d28cf000     0x5585d28d1000 r--p     2000 53000  /usr/bin/ssh-agent
    0x5585d28d1000     0x5585d28d2000 ---p     1000 55000  /usr/bin/ssh-agent
    0x5585d28d2000     0x5585d28d4000 ---p     2000 0      load4
    0x5585d30b2000     0x5585d30f4000 ---p    42000 0      load5
    0x7f8c729a6000     0x7f8c729a8000 ---p     2000 0      load6
    0x7f8c729a8000     0x7f8c729ae000 r--p     6000 0      /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
    0x7f8c729c5000     0x7f8c729c6000 r--p     1000 1c000  /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
    0x7f8c729c6000     0x7f8c729c7000 ---p     1000 1d000  /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
    0x7f8c729c7000     0x7f8c729cb000 ---p     4000 0      load10
    0x7f8c729cb000     0x7f8c729cc000 r--p     1000 0      /usr/lib/x86_64-linux-gnu/libdl-2.31.so
    0x7f8c729cf000     0x7f8c729d0000 r--p     1000 3000   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
    0x7f8c729d0000     0x7f8c729d1000 ---p     1000 4000   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
    0x7f8c729d1000     0x7f8c729f3000 r--p    22000 0      /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7f8c72bb9000     0x7f8c72bbd000 r--p     4000 1e7000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7f8c72bbd000     0x7f8c72bbf000 ---p     2000 1eb000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7f8c72bbf000     0x7f8c72bc3000 ---p     4000 0      load17
    0x7f8c72bc3000     0x7f8c72c3b000 r--p    78000 0      /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
    0x7f8c72e67000     0x7f8c72e93000 r--p    2c000 2a3000 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
    0x7f8c72e93000     0x7f8c72e95000 ---p     2000 2cf000 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
    0x7f8c72e95000     0x7f8c72e9b000 ---p     6000 0      load21
    0x7f8c72e9e000     0x7f8c72e9f000 r--p     1000 0      /usr/lib/x86_64-linux-gnu/ld-2.31.so
    0x7f8c72ecb000     0x7f8c72ecc000 r--p     1000 2c000  /usr/lib/x86_64-linux-gnu/ld-2.31.so
    0x7f8c72ecc000     0x7f8c72ecd000 ---p     1000 2d000  /usr/lib/x86_64-linux-gnu/ld-2.31.so
    0x7f8c72ecd000     0x7f8c72ece000 ---p     1000 0      load25
    0x7ffe2962f000     0x7ffe29650000 rw-p    21000 0      [stack]
    0x7ffe2975b000     0x7ffe2975d000 r-xp     2000 0      load27
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```
This shows a few things
1. There isn'ta segment marked as heap
2. There is a stack though
3. It has some segments marked as `load4`, `load5`, `load25`, etc. which have different sizes.

Telescoping the stack shows something interesting:
```
pwndbg> telescope rsp
00:0000│ rsp 0x7ffe2964df58 ◂— 0x5585d28838d1
01:0008│     0x7ffe2964df60 ◂— 0xffff6
02:0010│     0x7ffe2964df68 —▸ 0x7ffe2964dfa0 ◂— 0x1
03:0018│     0x7ffe2964df70 ◂— 0x5
04:0020│     0x7ffe2964df78 ◂— 0xffff6
...
...
1b:00d8│  0x7ffe2964e030 —▸ 0x7f8c72bc22e8 (X509_verify_cert+296) ◂— 0x0
1c:00e0│  0x7ffe2964e038 ◂— 0x5585d28a7550
```
At an offset of `0x00d8` from `rsp`, there is a pointer to `X509_verify_cert+296` which sounds interesting from the name. It seems to be doing some x509 cert verification judging from the name, which might be useful because it's at least something. It doesn't really come in too handy later on but for now it gives us some hanlde on things.

```
pwndbg> p &X509_verify_cert
$2 = (<text variable, no debug info> *) 0x7f8c72bc21c0 <__pthread_keys+10016>
```

#### Looking in source code

The source code can be found at https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c 

One interesting thing I saw was on line 2229:
```
#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
```
Interesting that it prevents coredump, but we already have it provided for us. But one thing it tells us is that we're looking in the right place (source code) for private keys, it does store it in memory somewhere---we just need to find where.


Next, looking through the source, I found the `reaper()` function which "removes expired keys and returns number of seconds until the next expiry". This seems interesting because in order to remove the expired keys, the program would have to access the location where the keys are stored. So, we can follow the logic to get to that location. I was able to also find it in Ghidra.

To find the function in gdb, I tried looking for the string and matching instructions, as well as tried other things. At this point, I was focusing on function in the source code finding them and in Ghidra and then locating them in gdb. I was using a gdb session of the ssh-agent binary without the coredump.

I spent some time looking for and analysing the reaper function, it ultimately wasn't as useful as I had hoped but I did get a few important insights from it. In the source code for the `reaper()` function, there are interesting variables being used.
1. The variables of type `Identity`:
```
	Identity *id, *nxt;
```
1. There is pointer being used to get what seems to be a linked list of identities:
```
	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
        ...
        			TAILQ_REMOVE(&idtab->idlist, id, next);
                    ...
        ...
```
The `idtab` variable looks very interesting beacuse it either is the place where the identities are stored or is a handle to where the identities are stored.

### Looking for functions

I looked for the `main()` function by starting gdb and then stepping through the instructions in `__libc_start_main` until I came to this point:
```
► 0x7ffff7801e3b <__libc_start_main+123>    call   __libc_start_call_main                <__libc_start_call_main>
        rdi: 0x55555555c1d0 ◂— endbr64 
        rsi: 0x1
        rdx: 0x7fffffffda78 —▸ 0x7fffffffde3d ◂— '/home/zaid/CTFs/NSA22/task_5/downloads/ssh-agent'
```
The value in `rdi` is a pointer to a some instructions. I inspected the instructions at that location and compared with Ghidra and source code to see if this was `main()`. I looked for the Ghidra function by looking at the last bytes, because even with ASLR, the last bytes remain same. One indication is the use of `getgid()` and `setegid()`. The functions matched and so I was fairly sure that this was `main()`.

As I was working on reverse engineering, I kept note and track of the locations of functions in a separate file and I also prefixed the Ghidra function names with the actual names (as I understood).

I also looked at the coredump and it didn't seem to have any code sections, which made me drop looking for functions in it and decided to find the private key storage location in the gdb binary (without coredump) and then correspond it in the coredump later. 

I also did a similar approach to find `sanitise_stdfd()`, `platform_disable_tracing()`, `ssh_get_progname()` and `seed_rng()` in gdb.

There was a problem executing `platform_disable_tracing()` but if I jumped over it, things worked fine.

While looking through the source code, I found that in line 2145, it calls the function `getpid()` and then stores the value in `parent_pid`. 
```
	parent_pid = getpid();
```
In Ghidra, this looked like this:
```
DAT_00156014 = getpid();
```

This is interesting because the variable is a global variable---declared as a global variable in the source code, and assigned to a `DAT_` variable in Ghidra which means that it is a global variable. And that is interesting because these are usually stored in the heap segment. So, if we can correspond the section in the coredump, then we can find the segment which is should have the private key, making the reasonable assumption that the private key is stored using `malloc` and in the heap. In gdb, the instruction looked like this:
```
► 0x55555555c55f    mov    dword ptr [rip + 0x4daaf], eax
```
So, the value gets stored at `rip + 0x4daaf`. Let's see what it looks like around there:
```
pwndbg> telescope $rip+0x4daaf
00:0000│  0x5555555aa00e ◂— 0xffff000000020000
01:0008│  0x5555555aa016 ◂— 0x20ffffffffffff
02:0010│  0x5555555aa01e ◂— 0x1000000020000
03:0018│  0x5555555aa026 ◂— 0x30000
04:0020│  0x5555555aa02e ◂— 0xffffffffffff0000
05:0028│  0x5555555aa036 ◂— 0x10000003fffff
06:0030│  0x5555555aa03e ◂— 0x10000
07:0038│  0x5555555aa046 ◂— 0x555555582a880000

pwndbg> vmmap $rip+0x4daaf
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x5555555aa000     0x5555555ab000 rw-p     1000 55000  /home/zaid/CTFs/NSA22/task_5/downloads/ssh-agent +0xe
```
The address is at an offset of `+0xe` in the vmmap segment. The vmmap segment is of size `1000` and matches with the coredump vmmap segment:
```
    0x5585d28d1000     0x5585d28d2000 ---p     1000 55000  /usr/bin/ssh-agent
```
Now, lets see what is at the same offset in the coredump segment:
```
pwndbg> telescope 0x5585d28d1000+0xe
00:0000│  0x5585d28d100e ◂— 0x12000000020000
01:0008│  0x5585d28d1016 ◂— 0x20ffffffff0000
02:0010│  0x5585d28d101e ◂— 0x20000
03:0018│  0x5585d28d1026 ◂— 0x30000
04:0020│  0x5585d28d102e ◂— 0xffffffffffff0000
05:0028│  0x5585d28d1036 ◂— 0x10000003fffff
06:0030│  0x5585d28d103e ◂— 0x10000
07:0038│  0x5585d28d1046 ◂— 0x5585d28a9a880000
```
If we look at the values stored here, they are exactly the same, except for the first one which I assume is going to be assigned after the instruction or later. This tells us that we are probably looking at the right location for where the `parent_pid` is stored. We can also assume that around this place is where the global variables are stored.

At this point, the program forks a child process at line 2190 in the source code. In Ghidra, at line 155:
```
pid_Var7 = fork();
```
We want to follow the child process because the parent executes some logic and then exits. In the source, lines 2195-2215:
```
	if (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, sizeof pidstrbuf, "%ld", (long)pid);
		if (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		if (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
```
For that, we can set the option in gdb: `set follow-fork-mode child`. FOllowing the child is useful because it sets up some sockets and calls some ssh related functions: (lines 2241-2251)
```
#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);

```

I then continued to look for interesting functions which references id related structs or arguments, etc. I saw the `pkcs11_init()` function which I looked into. It seemed to be initialising some stroage for pkcs providers. The source was at: https://github.com/openssh/openssh-portable/blob/97f9b6e61316c97a32dad94b7a37daa9b5f6b836/ssh-pkcs11.c. I didn't find too much here.

I also found the `idtab_init()` function which I thought was potentially very important. The function is very short but it importantly assigns `idtab` (I thought it was potentially important but didn't realise it's full importance at the time). The function is at lines 210-216:
```
static void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}
```
Looking at what exactly idtab is at lines 149-155:
```
struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable *idtab;
```
It looks like a linked list of identities.

The `xcalloc` uses `sizeof(*idtab)` which is `0x18` when I break at the function call and look at arguments and also according to Ghidra. The calloc return value was ` RAX  0x5555555c9140 ◂— 0x0 ` which then got stored into the `idtab` global variable as: ` 0x5555555aa7c0 —▸ 0x5555555c9140 ◂— 0x0` (in gdb). 
The instructions in Ghidra looked like this (I renamed the idtab_init function):
```
        puVar14 = (undefined4 *)idtab_init_FUN_0011baf0(1,0x18);
        DAT_001567c0 = puVar14;
```

Looking at the vmmap for this gdb address and telescoping:
```
pwndbg> vmmap 0x5555555aa7c0
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x5555555aa000     0x5555555ab000 rw-p     1000 55000  /home/zaid/CTFs/NSA22/task_5/downloads/ssh-agent +0x7c0

pwndbg> telescope $rip+0x4d8dc
00:0000│  0x5555555aa7c0 —▸ 0x5555555c9140 ◂— 0x0
01:0008│  0x5555555aa7c8 ◂— 0x0
... ↓     2 skipped
04:0020│  0x5555555aa7e0 ◂— '/tmp/ssh-avGuDr88j45x/agent.54645'
05:0028│  0x5555555aa7e8 ◂— '-avGuDr88j45x/agent.54645'
06:0030│  0x5555555aa7f0 ◂— '8j45x/agent.54645'
07:0038│  0x5555555aa7f8 ◂— 'ent.54645'
```

The vmmap segment in the coredump which looks similar to this one is (see above for full coredump vmmap):
```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
...
    0x5585d28d1000     0x5585d28d2000 ---p     1000 55000  /usr/bin/ssh-agent
...
```

Looking at the same offset in this coredump segment:
```
pwndbg> telescope 0x5585d28d1000+0x7c0
00:0000│  0x5585d28d17c0 —▸ 0x5585d30ce3c0 ◂— 0x1
01:0008│  0x5585d28d17c8 ◂— 0x0
... ↓     2 skipped
04:0020│  0x5585d28d17e0 ◂— '/tmp/ssh-gH19cuv11Hop/agent.18'
05:0028│  0x5585d28d17e8 ◂— '-gH19cuv11Hop/agent.18'
06:0030│  0x5585d28d17f0 ◂— '11Hop/agent.18'
07:0038│  0x5585d28d17f8 ◂— 0x38312e746e65 /* 'ent.18' */
```
We can see that it looks similar, so we can make a reasonable conclusion that this is where the `idtab` global variable is stored in the coredump. 



> I did a bunch of stuff here at this point, before and during resolving the idtab location in gdb and the coredump, which was me tryng different things to see if something works.
> I was looking at things related to the address that calloc returns. I wasn't seeing the address in the heap chunks and was trying to figure things out related to that.
> I also looked at some stuff related to the `prepare_poll()` and `poll()` functions.
> I also looked at the (returned) `pkcs11_provider` struct, the `pkcs11_provider_lookup()` function, the `pkcs11_key` struct, etc. I looked at these because I thought these would lead me some place where the identities are managed, because pkcs11 seemed related.
>
> While I was doing these things, I also stumbled upon a region (when looking at the calloc pointers) which seemed to hold a lot of pointers to places and I was thinking this was useful and perhaps pointers to where the different identities are stored.
> ```
> 0x5585d30d2290: 0x00005585d30d22a0      0x0000000000000031
> pwndbg> 
> 0x5585d30d22a0: 0x00005585d30d03f0      0x00005585d30d1410
> 0x5585d30d22b0: 0x0000000000000000      0x0000000000000000
> 0x5585d30d22c0: 0x0000000000000030      0x00000000000000a0
> 0x5585d30d22d0: 0x0000000000000000      0x00005585d30b2010
> 0x5585d30d22e0: 0x00005585d30d1a50      0x00005585d30d1ad0
> 0x5585d30d22f0: 0x00005585d30d1b50      0x00005585d30d1bf0
> 0x5585d30d2300: 0x00005585d30d1c50      0x00005585d30d1d30
> 0x5585d30d2310: 0x00005585d30d1d90      0x00005585d30d1e30
> 0x5585d30d2320: 0x00005585d30d1f00      0x00005585d30d1f60
> 0x5585d30d2330: 0x00005585d30d21f0      0x00005585d30d2270
> 0x5585d30d2340: 0x0000000000000000      0x0000000000000000
> ```
> The pointers seemed to be in chunks, where there would be a bunch of null 64-bit values in between locations that have multiple 64-bit pointers.
>
> Telescoping to see what these are:
> ```
> pwndbg> telescope 0x5585d30d2290
> 00:0000│  0x5585d30d2290 —▸ 0x5585d30d22a0 —▸ 0x5585d30d03f0 —▸ 0x5585d30d0400 —▸ 0x7f8c72bbdc00 (X509_TRUST_get_by_id) ◂— ...
> 01:0008│  0x5585d30d2298 ◂— 0x31 /* '1' */
> 02:0010│  0x5585d30d22a0 —▸ 0x5585d30d03f0 —▸ 0x5585d30d0400 —▸ 0x7f8c72bbdc00 (X509_TRUST_get_by_id) —▸ 0x5585d30d3160 ◂— ...
> 03:0018│  0x5585d30d22a8 —▸ 0x5585d30d1410 —▸ 0x5585d30d1420 —▸ 0x5585d30d2290 —▸ 0x5585d30d22a0 ◂— ...
> 04:0020│  0x5585d30d22b0 ◂— 0x0
> 05:0028│  0x5585d30d22b8 ◂— 0x0
> 06:0030│  0x5585d30d22c0 ◂— 0x30 /* '0' */
> 07:0038│  0x5585d30d22c8 ◂— 0xa0
> 08:0040│  0x5585d30d22d0 ◂— 0x0
> 09:0048│  0x5585d30d22d8 —▸ 0x5585d30b2010 ◂— 0x7000400070007
> 0a:0050│  0x5585d30d22e0 —▸ 0x5585d30d1a50 ◂— 0x0
> 0b:0058│  0x5585d30d22e8 —▸ 0x5585d30d1ad0 ◂— 0x0
> 0c:0060│  0x5585d30d22f0 —▸ 0x5585d30d1b50 —▸ 0x5585d30d1a40 ◂— 0x0
> 0d:0068│  0x5585d30d22f8 —▸ 0x5585d30d1bf0 ◂— 0x0
> 0e:0070│  0x5585d30d2300 —▸ 0x5585d30d1c50 ◂— 0x0
> 0f:0078│  0x5585d30d2308 —▸ 0x5585d30d1d30 ◂— 0x0
> 10:0080│  0x5585d30d2310 —▸ 0x5585d30d1d90 ◂— 0x0
> 11:0088│  0x5585d30d2318 —▸ 0x5585d30d1e30 —▸ 0x5585d30d1c40 ◂— 0x0
> 12:0090│  0x5585d30d2320 —▸ 0x5585d30d1f00 ◂— 0x0
> 13:0098│  0x5585d30d2328 —▸ 0x5585d30d1f60 ◂— 0x0
> 14:00a0│  0x5585d30d2330 —▸ 0x5585d30d21f0 ◂— 0x0
> 15:00a8│  0x5585d30d2338 —▸ 0x5585d30d2270 ◂— 0x0
> 16:00b0│  0x5585d30d2340 ◂— 0x0
> 17:00b8│  0x5585d30d2348 ◂— 0x0
> ```
>
> I did some stuff with this and tried to format it as a key and use it decrypt the `data.enc` file, decode with asn1, etc. but those things didn't work because it was wrong and this is not the key or the identities.
>
> I spent a lot of time on these tangents. But realising that I could and should follow the `idtab` variable because it is a global variable was a **clicking point** for me.

### Looking for `idtab` and shielded private key

Going back to following `idtab`, the following structs and definitions are useful:
```
struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};
```
```
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}
```
```
typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
	char *sk_provider;
	struct dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;
```
```
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
```

In the coredump, the address where the idtab global variable is located is `0x5585d28d17c0` corresponding to the same offset in the vmmap region. It points to this location:
```
pwndbg> telescope 0x5585d28d1000+0x7c0
00:0000│  0x5585d28d17c0 —▸ 0x5585d30ce3c0 ◂— 0x1
```

Then, the idtab struct (not the pointer to it) looks like this:
```
pwndbg> telescope 0x5585d30ce3c0
00:0000│  0x5585d30ce3c0 ◂— 0x1
01:0008│  0x5585d30ce3c8 —▸ 0x5585d30d3b90 ◂— 0x0
02:0010│  0x5585d30ce3d0 —▸ 0x5585d30d3b90 ◂— 0x0
03:0018│  0x5585d30ce3d8 ◂— 0x1e1
04:0020│  0x5585d30ce3e0 ◂— 0x0
05:0028│  0x5585d30ce3e8 —▸ 0x5585d30b2010 ◂— 0x7000400070007
06:0030│  0x5585d30ce3f0 ◂— 0x0
07:0038│  0x5585d30ce3f8 ◂— 0x0

pwndbg> x/4gx 0x5585d30ce3c0
0x5585d30ce3c0: 0x0000000000000001      0x00005585d30d3b90
0x5585d30ce3d0: 0x00005585d30d3b90      0x00000000000001e1
```

Now what we are going to do is try and manually parse the structs that are present in memory by using the definitions in the source code. So,`idtab` is an `idtable` struct and after resolving the `TAILQ_HEAD` macro, it should look like below. I have also added the values that correspond to the struct elements by corresponding it with the `x/4gx` command above.
```
struct idtable {
	int nentries; = 0x1
  struct idqueue idlist {								
    struct identity *tqh_first;	= 0x5585d30d3b90 ◂— 0x0  (only 1 elem so both first and last are same)
    struct identity **tqh_last;	= 0x5585d30d3b90 ◂— 0x0
  }
};
```
> This kind of manual parsing of the structs from the memory required a little guessing as well about the size of each data type and which value corresponds to which struct element, etc. For people following along, this wasn't something I did perfectly by just looking at it at first glance.

This shows us that there is only `0x1` entry in the `idtable` and the `tqh_first` and `tqh_last` both point to the same address. This is because there is only one entry in the idtable which is a double-ended linked list. This single entry is located at `0x5585d30d3b90` and is of an `identity` struct. The struct definition for an `identity` (with the macros resolved) along with the values for each element are below:
```
typedef struct identity {			
  struct {								
    struct identity *tqe_next;  = 0x0
    struct identity **tqe_prev;	= 0x5585d30ce3c8 —▸ 0x5585d30d3b90 ◂— 0x0 (prev -> idtab.idlist.tqhfirst -> this)
  } next;

	struct sshkey *key; = 0x5585d30d1ee0 ◂— 0x0
	char *comment;      = 0x5585d30cfc00 ◂— 'T5upqypQDpDE9kBYlQsOAw'
	char *provider;     = 0x0000000000000000
	time_t death;       = 0x0000000000000000
	u_int confirm;
	char *sk_provider;
	struct dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;
```
The `TAILQ_ENTRY` looks like this, defined in [this file](https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/openbsd-compat/sys-queue.h):
```
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
```

From this, we can see that the `identity` holds a pointer to an `sshkey` struct and the value for this pointer is `0x5585d30d1ee0`. Telescoping and examining this address:
```
pwndbg> telescope 0x5585d30d1ee0
00:0000│  0x5585d30d1ee0 ◂— 0x0
01:0008│  0x5585d30d1ee8 —▸ 0x5585d30d50e0 ◂— 0x0
02:0010│  0x5585d30d1ef0 ◂— 0x0
03:0018│  0x5585d30d1ef8 ◂— 0xffffffff
04:0020│  0x5585d30d1f00 ◂— 0x0
... ↓     3 skipped

pwndbg> x/24gx 0x5585d30d1ee0
0x5585d30d1ee0: 0x0000000000000000      0x00005585d30d50e0
0x5585d30d1ef0: 0x0000000000000000      0x00000000ffffffff
0x5585d30d1f00: 0x0000000000000000      0x0000000000000000
0x5585d30d1f10: 0x0000000000000000      0x0000000000000000
0x5585d30d1f20: 0x0000000000000000      0x0000000000000000
0x5585d30d1f30: 0x0000000000000000      0x0000000000000000
0x5585d30d1f40: 0x0000000000000000      0x0000000000000000
0x5585d30d1f50: 0x0000000000000000      0x0000000000000000
0x5585d30d1f60: 0x0000000000000000      0x00005585d30d4ab0
0x5585d30d1f70: 0x0000000000000570      0x00005585d30d5c00
0x5585d30d1f80: 0x0000000000004000      0x0000000000000031
0x5585d30d1f90: 0x00005585d30d1650      0x00007f8c72bbdc00
```

Parsing the sshkey struct:
```
struct sshkey *key; = 0x5585d30d1ee0 ◂— 0x0
key @ `0x5585d30d1ee0`

struct sshkey {
	int	 type;        = 0x00000000
	int	 flags;       = 0x00000000
	/* KEY_RSA */
	RSA	*rsa;         = 0x00005585d30d50e0
	/* KEY_DSA */
	DSA	*dsa;         = 0x0000000000000000
	/* KEY_ECDSA and KEY_ECDSA_SK */
	int	 ecdsa_nid;	/* NID of curve */    = 0x00000000ffffffff
	EC_KEY	*ecdsa;                       = 0x0000000000000000
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;                  = 0x0000000000000000
	u_char	*ed25519_pk;                  = 0x0000000000000000
	/* KEY_XMSS */
	char	*xmss_name;                     = 0x0000000000000000
	char	*xmss_filename;	/* for state file updates */  = 0x0000000000000000
	void	*xmss_state;	/* depends on xmss_name, opaque */  = 0x0000000000000000
	u_char	*xmss_sk;                     = 0x0000000000000000
	u_char	*xmss_pk;                     = 0x0000000000000000
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	char	*sk_application;                = 0x0000000000000000
	uint8_t	sk_flags;                     = 0x0000000000000000
	struct sshbuf *sk_key_handle;         = 0x0000000000000000
	struct sshbuf *sk_reserved;           = 0x0000000000000000
	/* Certificates */
	struct sshkey_cert *cert;             = 0x0000000000000000
	/* Private key shielding */
	u_char	*shielded_private;            = 0x00005585d30d4ab0
	size_t	shielded_len;                 = 0x0000000000000570
	u_char	*shield_prekey;               = 0x00005585d30d5c00
	size_t	shield_prekey_len;            = 0x0000000000004000
};

```

This struct has something described as private key shielding. It also has an `RSA *rsa` value but that wasn't very helpful. Let's try and see what is stored at the addresses for `shielded_private` and `shield_prekey`; they also have the corresponding lengths which is useful.

The `shielded_private` length is `0x570` and in 64-bit addressing, we want to examine:
```
pwndbg> x/174gx 0x00005585d30d4ab0
0x5585d30d4ab0: 0x8b44180d6f8017fe      0x4f490242e641b746
0x5585d30d4ac0: 0x2d6a123566a36b9e      0xf9155b0655a2a9f1
0x5585d30d4ad0: 0x06b8470b89678f8e      0x4780366363538f44
0x5585d30d4ae0: 0x9c598b53900e5684      0x2653bc4f9351f923
0x5585d30d4af0: 0x87d93aa6a98fa707      0x5978a0df28a94128
0x5585d30d4b00: 0x0122c3dc8f0d3226      0x29eb41959cf1de1d
0x5585d30d4b10: 0xe01d1cfa645e12ff      0x45fde0c6302cbc0e
0x5585d30d4b20: 0x63d277a1dc7ed391      0x83da0930efa33199
0x5585d30d4b30: 0x4a37ed9ca8237d18      0x1560015ec4008999
0x5585d30d4b40: 0x8a6039f46f0e7ed7      0x11fb7a0cee4bc8c8
0x5585d30d4b50: 0x75aae05c832d86c2      0x07facd4decae460a
0x5585d30d4b60: 0xf99371f381b4833f      0x729523aeb85c3438
0x5585d30d4b70: 0x38b8e7d796d226f8      0xeb2aa45089ea9fab
0x5585d30d4b80: 0x9894df0067ba512b      0x5e7e1af3ced556ca
0x5585d30d4b90: 0x9ae29912ffa9da18      0x9149fdb99bf23678
0x5585d30d4ba0: 0x6ee0146d8f0d6d30      0x4adb2dab7d7ae42a
0x5585d30d4bb0: 0xb8b6e296d207e3f1      0x966479f50abc5d83
0x5585d30d4bc0: 0xba6a25745a57a898      0x64cf2cc3ff6d41e0
0x5585d30d4bd0: 0x81c6530bf542ed80      0x5bf9723a8b015595
0x5585d30d4be0: 0xb73f30921ea8fc3c      0xe7fcd4b552cd04f0
0x5585d30d4bf0: 0x792f5955b54aebdf      0xc6a9accc707ae9c0
0x5585d30d4c00: 0x7afb3e8bc3c3661e      0xcd3a5fc01a3f3458
0x5585d30d4c10: 0xf37ef1383a011956      0x4e3407943a808e3c
0x5585d30d4c20: 0x65eccfd8eadd621b      0x5cbc3a756c354373
0x5585d30d4c30: 0x84c4382dc570623b      0x966356cf6bbb90f5
0x5585d30d4c40: 0x2f80f8518e5538b3      0xf1717e1b05eb6372
0x5585d30d4c50: 0x861faba9634a81a8      0x46ab0e7e30af6705
0x5585d30d4c60: 0xd0c6539bec378f21      0xa39f55a6494b70bf
0x5585d30d4c70: 0x1ae2c4a824e7a816      0x8754253e3d5522dd
0x5585d30d4c80: 0xc8411667525729cc      0xf79c32e4eb0a6784
0x5585d30d4c90: 0x9a8a4af8a230b7c0      0x46c0f590342dd31a
0x5585d30d4ca0: 0x138698c7e8392929      0xfe7670e7d898900b
0x5585d30d4cb0: 0x9d7765e6ad3b4e6e      0xb74018118ccbc2bf
0x5585d30d4cc0: 0x1a604146086d1612      0xac346914d5195df3
0x5585d30d4cd0: 0x2618bcc03024a5c8      0x63fa829d8bac6355
0x5585d30d4ce0: 0x2cf1d51b23285031      0xbff3eea4452d6367
0x5585d30d4cf0: 0xf95925c927b6dbca      0xfd89ebde751e2c2b
0x5585d30d4d00: 0xa219aaa2a90d69bb      0x93f6f2d6cd04ec25
0x5585d30d4d10: 0x0ae136b1417499a8      0xfe34fc180d902bd3
0x5585d30d4d20: 0x8bba0999c3c06b4d      0x78303a39113b89c7
0x5585d30d4d30: 0x2f211b23d1978177      0x8f67e7105541c431
0x5585d30d4d40: 0xa03af6f29ba057ca      0x51fc114d1b1a84cb
0x5585d30d4d50: 0x0998e01cb16d811f      0x35f1756f74eafa7d
0x5585d30d4d60: 0x2defc08610dfe473      0xb7cefa5f2b062500
0x5585d30d4d70: 0xea03a20f8a2cc70d      0xdedc984992102403
0x5585d30d4d80: 0x5f004ee2a4e85b89      0xcb9a72682d6627a5
0x5585d30d4d90: 0xd62061e1d92c9cd0      0x71b81f98b9b459f3
0x5585d30d4da0: 0x1c4ce9432219910d      0xba09f8f23423b121
0x5585d30d4db0: 0x92d5597fe5e75495      0x81e6e75f0e501745
0x5585d30d4dc0: 0x7bf7f9714056caf5      0xc9107bf6e78dbf35
0x5585d30d4dd0: 0x3e86276578ff5396      0x21d2641a7cc3bea7
0x5585d30d4de0: 0xf17da7b0e34cb922      0x1e44632314f327f6
0x5585d30d4df0: 0xcbedb904ab420e1d      0x471838e210aac786
0x5585d30d4e00: 0x7fc3d1e0ee415a34      0xae68f1f3a25f9668
0x5585d30d4e10: 0x4828448e395b5a9b      0x97f4b23c58a4669d
0x5585d30d4e20: 0x35cc0b8ef6ef2b87      0x7e59b4cc3ba220de
0x5585d30d4e30: 0xaea98f373f3e2bae      0x244691453f4b1650
0x5585d30d4e40: 0xf2a27ccfcc595d5f      0x693d62b236ee5035
0x5585d30d4e50: 0xae0bde7f5d68013c      0x3260a0315468e461
0x5585d30d4e60: 0x4506b83655a44a25      0x08e410f5a671565c
0x5585d30d4e70: 0x6f67f3e4e2f1f74a      0xf0c5155ff0cdcb68
0x5585d30d4e80: 0xa27754778a47f308      0xb9f82dfe6eca112b
0x5585d30d4e90: 0x37a4ec35a5712598      0xaa22f5c90f85fbec
0x5585d30d4ea0: 0xb35e5e8cdca0feb0      0x4593a24d3b80c27a
0x5585d30d4eb0: 0x36dfc72a9aba103b      0xd0d5ba575dc34b0b
0x5585d30d4ec0: 0xbb1d75c6d371f6e2      0x26b0b4e1eec5e6a7
0x5585d30d4ed0: 0x2c85b8301e5fe775      0xf2af7460c2ab330c
0x5585d30d4ee0: 0x3c7349b249c9991c      0xd72026bc16091035
0x5585d30d4ef0: 0x262c97d357b3cfec      0xad3fbf26362b6ca5
0x5585d30d4f00: 0x8d8434d6ab078de4      0x9045662915f8e76a
0x5585d30d4f10: 0x3a0f4129deadff4e      0xc9107e8a0585d236
0x5585d30d4f20: 0xd339f4dd78c834df      0x88a4665bf8c815a2
0x5585d30d4f30: 0x43c4ee6d04013ccd      0x8d278b602155e1f5
0x5585d30d4f40: 0xde4341f9ff7b16ce      0x0edec09f888d1012
0x5585d30d4f50: 0x522dd8bb38ccdbc0      0x8fa1aff7e5e8a805
0x5585d30d4f60: 0x2481a1fdf7826ad4      0x631c1b2bf3760efc
0x5585d30d4f70: 0xa43fac76377028da      0x122e30266c63ba56
0x5585d30d4f80: 0x2addb59eb8d46fa5      0x740eec5e1dccbc2b
0x5585d30d4f90: 0x66d49758d8b887ff      0x6b700919c690268f
0x5585d30d4fa0: 0xaa61cdd31f6f2155      0x6c02d92ace680283
0x5585d30d4fb0: 0x562fc6d6cd63988f      0x9f80c02d4ad366ef
0x5585d30d4fc0: 0x8a38d6c29e5d5465      0x109a60e97da95130
0x5585d30d4fd0: 0x8d44eeba3c8e1865      0xbe72ddea5198b862
0x5585d30d4fe0: 0x63b59ee0b90f531d      0xdd409c7cc2bb2eb1
0x5585d30d4ff0: 0xe0f959f330287a26      0x8df66e630942ca12
0x5585d30d5000: 0xbded2c64436b3949      0x27532c5c43105121
0x5585d30d5010: 0x120b3307f2f07f79      0xdcd3ac65d37329b0
pwndbg> 
0x5585d30d5020: 0x0000000000000000      0x00000000000000b1
```
We can see that it ends with null bytes.

Similarly, the `shield_prekey` is of length `0x4000` at address `0x00005585d30d5c00`
```
pwndbg> x/2048gx 0x00005585d30d5c00
0x5585d30d5c00: 0x5b6f73e215957b73      0x9b35dd973f5b7838
0x5585d30d5c10: 0xbfbeb5fb6ff66b32      0x3036ef3496a56943
0x5585d30d5c20: 0xb7b78b39289d6c7d      0x3b98c2907b014c75
0x5585d30d5c30: 0x6afbeec92f58f1ea      0x316d3f352bbd1fdf
0x5585d30d5c40: 0xccf93bbef8ea7607      0x21c76ca7abf91071
0x5585d30d5c50: 0xcc2bbe1b9d1cbd4e      0x692c2a93214d4158
0x5585d30d5c60: 0xf7cf561ef348f49f      0xb509c18ebeeec19c
0x5585d30d5c70: 0x66dbbda9f2f7b1b8      0x5577a6e429b51b65
0x5585d30d5c80: 0xd8550219023336b5      0x451662a255da825c
0x5585d30d5c90: 0x3e21080f7da61c38      0x2f8db3c56e3be2c6
0x5585d30d5ca0: 0x1dcff36d7b60fc82      0x2fb55976f181d26b
0x5585d30d5cb0: 0x9c025d2c2a215a84      0xa2cc93e14717ee50
0x5585d30d5cc0: 0x2b0388c24bc29ffe      0x3f249ec7c1efdaef
0x5585d30d5cd0: 0x68287d82d020b3fb      0x673cc78365ac13b6
0x5585d30d5ce0: 0xb2995e0bbe48a8c6      0xb9e812885d534ea6
0x5585d30d5cf0: 0x28b1501be05876f3      0xfc36cd7f7ed387ba
0x5585d30d5d00: 0x201956496f36974b      0xc677e223a3d33787
0x5585d30d5d10: 0xa995cbcb51855c38      0xd0e9748be564f667
0x5585d30d5d20: 0x53e5b3436c8be869      0xfe76e2a3ce65851d
0x5585d30d5d30: 0x3b1efc6f41db6f59      0x40dc2954c8aa8fa3
0x5585d30d5d40: 0x31f09c55e6dc9296      0xcbd189e5b511d23e
0x5585d30d5d50: 0x8b3bea32e6d5bf49      0xf6b4386942dabf16
0x5585d30d5d60: 0x03500129d442c2a7      0x7d6a91241f2fa32d
0x5585d30d5d70: 0x4d6b3085935cb034      0xb87e4230988b623c
0x5585d30d5d80: 0xfcb8b99a0b3a9903      0xcfe39ad622dd7cdf
0x5585d30d5d90: 0xb2d4c96ea7ca1b61      0xa9563b1f0bca23e0
0x5585d30d5da0: 0xa896eb9d8b90d8da      0xbcc1dfba9afa83b3
0x5585d30d5db0: 0x4639187818969e44      0xed870c0a0fe7711c
0x5585d30d5dc0: 0xfb6a9fd6cf12408f      0xed784ed86c500105
0x5585d30d5dd0: 0xc0ea4e47f3e65665      0x09ca6ac32e10ba8c
0x5585d30d5de0: 0xf15f2e4089f42949      0x818182f55136d8e3
0x5585d30d5df0: 0x9e45b8c335dc1823      0x3645fe02773b2da9
0x5585d30d5e00: 0xd4db5b9e98821d21      0x90f8578aa1d3d400
0x5585d30d5e10: 0x06fa0d63efb69fcb      0x1d55c8b18555e9aa
0x5585d30d5e20: 0xefde4d8256721f1f      0xc2b68325b8370528
0x5585d30d5e30: 0x8914ac4f51f2c9dc      0x94affd663b97f889
0x5585d30d5e40: 0x302e67e4280881c4      0x26053cbc09e1828c
0x5585d30d5e50: 0x66e2fac05245697e      0x8c1495cc9db951d2
0x5585d30d5e60: 0x2426ff5b7fe8adbf      0xe774d98d5b3fede1
0x5585d30d5e70: 0xe3b9bf7e90e702f2      0x08b5053d750aeb72
0x5585d30d5e80: 0x00d988762cf0aae0      0xbdb4a77342ccc4c3
0x5585d30d5e90: 0xda3a1b5d3e140522      0xbf689c4e032d1d5a
0x5585d30d5ea0: 0x8dfbe320df4bf2ba      0xb986c59f00274807
0x5585d30d5eb0: 0x6be324bc0f62f7ba      0x2f4c6340fea1116f
0x5585d30d5ec0: 0x891142aa6409d4ac      0x2fa18eef779f69a6
0x5585d30d5ed0: 0xe6333d95f9fd7af6      0x37a01e33d5ed83d2
0x5585d30d5ee0: 0x58be091ef7bb93ac      0x1214e011c2ed2195
0x5585d30d5ef0: 0x1d06fa08d8c34b4f      0x23648b918db31943
0x5585d30d5f00: 0xc8f80e949a407818      0x0e6e4c8b5a59372d
0x5585d30d5f10: 0x71720d9c3a3fbe69      0x854029db5b8f123a
0x5585d30d5f20: 0x2b335f16b1888498      0x4dfecc658c3324b9
0x5585d30d5f30: 0x01b42f985e5c59cf      0xf5ded970454a3ca0
0x5585d30d5f40: 0x36a6ef5ff27220ed      0x6b919542dc25a09a
0x5585d30d5f50: 0xb3c65d7880ba63d9      0x9cc7aa23207eb77a
0x5585d30d5f60: 0xae2b2e932006bc10      0x100c822244688716
0x5585d30d5f70: 0x835eac78b1c441a5      0xef5c55546debb0f9
0x5585d30d5f80: 0x61e1058fa6fe8088      0x56904da6a272c4a8
0x5585d30d5f90: 0xa5255c9a62109766      0x64c98ded8670ecec
0x5585d30d5fa0: 0xaa4fb92a33045b1f      0xcb318e9020336794
0x5585d30d5fb0: 0x9f72209d564392af      0x44f1754de04e19b8
0x5585d30d5fc0: 0xfcea3dc3b3139045      0x9d9db96723c636fe
0x5585d30d5fd0: 0x95f2ffbbe8e8efd8      0x5ef58c8a10741bc0
0x5585d30d5fe0: 0x47b8dd00e11326d3      0x86342180a36299bb
0x5585d30d5ff0: 0xd887634dfb079060      0xb07bc3c88bd343ca
0x5585d30d6000: 0x8c80c518fd879254      0xcbcf1f1cfadcf4bf
0x5585d30d6010: 0xd89fd814f3c6eae1      0x03fb4f960f2501c9
0x5585d30d6020: 0xa303332ace47a63a      0xde130c534397599f
0x5585d30d6030: 0x9b01e64ba35aab51      0x73d4758b701e789f
0x5585d30d6040: 0xa77a4311d6bd6713      0x541e2f6219070d45
0x5585d30d6050: 0xbf4f6698069ecd3d      0x36d3857c488ee115
0x5585d30d6060: 0x72c5dd5ac52194c7      0xc50113419967964b
0x5585d30d6070: 0x612f0e4161e3e031      0x8cf99d85bc576414
0x5585d30d6080: 0x5e3086d2d354f8a4      0x43271a9b7f17000e
0x5585d30d6090: 0xbc5dec54e2102ab4      0xe4f7b39b76e3a700
0x5585d30d60a0: 0x2105bb911340cb36      0x5a63a30630e5a106
0x5585d30d60b0: 0x78596149ba43bd52      0xada609248515beaa
0x5585d30d60c0: 0x3924bc8838c82403      0xf4136edbaf9d4fc6
0x5585d30d60d0: 0x0d201f4caf3656c4      0xd9a1e4e5eb567d29
0x5585d30d60e0: 0x79b42c2207097699      0x3ecb5544eb674850
0x5585d30d60f0: 0xce91c3076fd69683      0x6c92d7551e9f5082
0x5585d30d6100: 0x8dfd3f43c0b7a547      0x4a355b181b445b75
0x5585d30d6110: 0xbdbb81563aba5383      0x5bd3069f3cce20e2
0x5585d30d6120: 0xdea0e7565fceb485      0x36b6dfd5ef17dcf4
0x5585d30d6130: 0x8fc01380ec246e79      0xb0fc9f9b4577f188
0x5585d30d6140: 0x4bce6c79df9f03f3      0x134cefab4eb84bd2
0x5585d30d6150: 0xccea66cc4c6484fb      0x16d9b7f302acf69f
0x5585d30d6160: 0x6908990d01681d46      0x22a48980dfa94149
0x5585d30d6170: 0x90b08b30037849dd      0x9d2bc41bb17501db
0x5585d30d6180: 0x7afbe6f72a04e959      0x00710caaf114f42d
0x5585d30d6190: 0xe500577ded8efb37      0xfe15592d9dd328e5
0x5585d30d61a0: 0xc8e5b8c069f520fb      0xe51a72dca2e888a3
0x5585d30d61b0: 0x46eb775ee271f6c3      0x34f4d7b10a70d1f3
0x5585d30d61c0: 0x1e51af1817d09cc1      0x1e321cbde2f4eef7
0x5585d30d61d0: 0x75fd5b9d5a59b668      0xcd7ba69227e1fb9f
0x5585d30d61e0: 0x6608bbbbfe693d53      0x8137bce12b8ab8be
0x5585d30d61f0: 0x94c11fea369c8880      0xc5a5726f74499aeb
0x5585d30d6200: 0x2046a3a6925c4147      0x755ca75de5f1a914
0x5585d30d6210: 0x47aad77f2028a48e      0xb1d8aaab673c12ff
0x5585d30d6220: 0x9350a859b5fe4939      0x8473711e0e157ea5
0x5585d30d6230: 0x92762d49ac5f96df      0x5de9ebaff8f0b04f
0x5585d30d6240: 0xa7b50e918254d59c      0xac92df540e7bf5bd
0x5585d30d6250: 0x489c8e52d2300179      0xd45f951aa212564f
0x5585d30d6260: 0x8f6ba3a56c5d96b6      0x91e6cc067f02bec1
0x5585d30d6270: 0x2bf06f06d2db4da7      0x60556b4f3abb7b34
0x5585d30d6280: 0xf4e9d237ab045d5a      0x370b8af16b15f60c
0x5585d30d6290: 0xe53fb3d7103fc031      0x1fe5090435928c7e
0x5585d30d62a0: 0x7b64278ab502b385      0xe84e3e591789cf12
0x5585d30d62b0: 0xb5af5ea72772775e      0x689e78186cf87edd
0x5585d30d62c0: 0x67604f31ee3d9c78      0x73847b6eeaad1567
0x5585d30d62d0: 0x9d3d75282792a921      0x7035c9e58da888e9
0x5585d30d62e0: 0x7ac4caf764929729      0x66506ca46504b94c
0x5585d30d62f0: 0x2a6268576fb27739      0x85f3bdc59db34d0c
0x5585d30d6300: 0x431ca8e8600fdcaf      0xb28c666e4745c2d5
0x5585d30d6310: 0xee514ca617dea3f7      0xdb7026ba4958f316
0x5585d30d6320: 0x6e371c1a54a2c062      0x3be345a47aff7811
0x5585d30d6330: 0xcbf2fa67937b75e2      0xe73e9133967ae570
0x5585d30d6340: 0x9a63e8e58bf05453      0xd9bb80b8da13b1d8
0x5585d30d6350: 0xe5e361f74a3a3871      0x3df83ffac8b4dda9
0x5585d30d6360: 0x565acc1dcc1d2073      0x63b254f55125cbec
0x5585d30d6370: 0x1cc024677bd97396      0x57e78a3540635008
0x5585d30d6380: 0xe3c5c024a8a4a428      0x8420da553815931e
0x5585d30d6390: 0x69ef9092f9262f13      0x01b870aa97bab44f
0x5585d30d63a0: 0x990e55f7335b6b76      0xe90b7b260e44da62
0x5585d30d63b0: 0xde4121b01b24b9be      0x1ad29e438a753cad
0x5585d30d63c0: 0x0097b91e574f796b      0x28f5b663b6101761
0x5585d30d63d0: 0x1e604939aecf52c7      0xf4e581cbc2bd496a
0x5585d30d63e0: 0x2ce6b83f65e21de1      0x668325c5f9dba172
0x5585d30d63f0: 0xcfda332b16002ef3      0x01998b69f09baea8
0x5585d30d6400: 0x60a37a98eae649cc      0x6f3dc77e3faf652c
0x5585d30d6410: 0xae867322cd5e4831      0x5649d30fcc614b4c
0x5585d30d6420: 0xb02e60eaa1398a34      0x169fea708897e2fd
0x5585d30d6430: 0x5c7446e15ae68966      0x180a1ecda570a338
0x5585d30d6440: 0x999c3ddadf950e09      0x258915f060ac15a8
0x5585d30d6450: 0x07211901e4b32569      0x139ec171fe17d6d8
0x5585d30d6460: 0x3155d10f27edd91c      0x1b05cf4bc5392b7e
0x5585d30d6470: 0xcb5dbe08b16bea67      0xe32a84ceba6e2a31
0x5585d30d6480: 0x22fa404a29f47bf2      0xe90ae9b789caa8f8
0x5585d30d6490: 0xc9b66f4556966d99      0xe8f98b03c7b9e573
0x5585d30d64a0: 0xc07c9709e9bc227b      0x12be01d239ce7a02
0x5585d30d64b0: 0x81fdedd229bfec68      0xc8ffb8125066bad2
0x5585d30d64c0: 0x337c2611ccb5b641      0xbba2a9e783a4aaba
0x5585d30d64d0: 0xc00452c1dac130f0      0xca8aa90a399f228a
0x5585d30d64e0: 0xe8718b7f31aa5d4c      0x342f559fcff42d28
0x5585d30d64f0: 0x4d0c5f3b379a24ec      0x56e8e08451bc7069
0x5585d30d6500: 0xd3ffe9ca544c88a3      0x0daf4f619112a244
0x5585d30d6510: 0x70ed4f65d7222734      0x8a8f07d39eb8aa18
0x5585d30d6520: 0x0e1ef5f0279b19ca      0x6aa167f9a3117c26
0x5585d30d6530: 0xbf51bb6f4e8594c1      0x0f6b224de34a8332
0x5585d30d6540: 0x8beed61112d91105      0x71a21da706193553
0x5585d30d6550: 0xb5eb24eefcf1d190      0x8d4315997fa08dc8
0x5585d30d6560: 0x3f1806ebb37e25ff      0x34dffd723164ad57
0x5585d30d6570: 0x548aeba50634f252      0x2338c0e978cfa7cf
0x5585d30d6580: 0x546b2745008d532d      0xebca3aca34f8a85e
0x5585d30d6590: 0xa4af151b5d46f225      0x5bda6eeeed86d613
0x5585d30d65a0: 0xdb7eb02d8e92a954      0x103e707ae88d38ad
0x5585d30d65b0: 0xb82b38db73e4835f      0x80556bcd20749661
0x5585d30d65c0: 0x0ac56777e334530b      0x3ac8c818bbb8be15
0x5585d30d65d0: 0x313d5613ddf94a65      0x694f0af235e2a2ec
0x5585d30d65e0: 0x810ebbf9eec7dcae      0x58b6dbe3dfa99a1e
0x5585d30d65f0: 0x26558565f0d30d23      0x366d3156ce0a01b5
0x5585d30d6600: 0x582c3b0acdc470f6      0x53ee580bde9a2607
0x5585d30d6610: 0xc3d09b19d94d877f      0x40d025bee3c3bad9
0x5585d30d6620: 0x09d095fca5bfae5b      0x948e4a4f086e49fd
0x5585d30d6630: 0x01b54f411e41f112      0x84ce1005955d7657
0x5585d30d6640: 0xda3f95d7b0eca93b      0x83a8e15ae310f340
0x5585d30d6650: 0x3fffb48aa7b08792      0x6ff99366fa78c7b8
0x5585d30d6660: 0x011b771aa24d544a      0x39b915172dc1c68d
0x5585d30d6670: 0xae82098130729108      0x20bc721a55889a86
0x5585d30d6680: 0xda4b93c26bdbde1d      0x8a09d9fb1fb6027b
0x5585d30d6690: 0x896233cd7386c542      0xa605f33e2ae3f856
0x5585d30d66a0: 0x43483c64cd4f2195      0xfa0e4f2165d2bb77
0x5585d30d66b0: 0xdab11bdd4f265626      0x73ba759b9858b1ff
0x5585d30d66c0: 0x42cb51c0cc5f05d0      0x985d5d2514142205
0x5585d30d66d0: 0x523048da8db64c7c      0x034fe620073f1cbe
0x5585d30d66e0: 0xffdc0b054f1dbf2e      0x44a012cb034b9686
0x5585d30d66f0: 0xf980a6212ba06430      0xe27e6e7bcd7ce844
0x5585d30d6700: 0x27efc23da5361a5f      0xd3a02ac2dfe6bafd
0x5585d30d6710: 0x17fc8cd0c6623ac5      0xc65391df9227956d
0x5585d30d6720: 0x3a48049e3cc3fc5e      0x086f78794571e09f
0x5585d30d6730: 0x8c1855bee7fa0d8a      0xe525ddd842caaf35
0x5585d30d6740: 0x50ca79dcf37cb167      0xd1b69efcf14f531f
0x5585d30d6750: 0x43c0b37e86865bf2      0x9ab6347d72322798
0x5585d30d6760: 0x4b2b39fdcc62250e      0x802f0a585592a99d
0x5585d30d6770: 0x29a51e533fa546f5      0xabf7546122c32173
0x5585d30d6780: 0x144cdc338d1601d1      0xf53e7ec85168d827
0x5585d30d6790: 0x57c4a4569cd97aa5      0xacb39b82fdce1545
0x5585d30d67a0: 0x4c509f579316a495      0x634b9efb6897b35b
0x5585d30d67b0: 0xf4ec8be9becbde88      0x90f650fe937e3e4c
0x5585d30d67c0: 0xda9edfdd321c1c87      0xcabfc325b932606a
0x5585d30d67d0: 0x0ff3563836b75bc3      0xb0fce57b9d2546df
0x5585d30d67e0: 0x9870644542d96e01      0x5077927259ad75ea
0x5585d30d67f0: 0xd54e2f8966d5c010      0x3c3555d3e37cea4e
0x5585d30d6800: 0x7a5fcb378474a832      0xe1ffa42b03a0f71f
0x5585d30d6810: 0xe1298db6e9f44053      0x0d9e4a7bdebd69b3
0x5585d30d6820: 0x79dece2e60e3eb43      0xa4f16e671d4e175c
0x5585d30d6830: 0x63694c0f61060efa      0x83fe4a54eafe0b6b
0x5585d30d6840: 0x148da2b826a4f408      0xe5bf5927df4da484
0x5585d30d6850: 0x1981dda57ddad644      0xa34aab004b02a502
0x5585d30d6860: 0xc5a315fa02d24314      0x9b6a0a0a4054e560
0x5585d30d6870: 0x3c161893c515f622      0x596261205ca62b70
0x5585d30d6880: 0x4fbc82c62468f79d      0xf7defcd87f4e0e23
0x5585d30d6890: 0x75db9459707d1c45      0xf41fcc653841ce7a
0x5585d30d68a0: 0x947d687a1e4dc40c      0x8bc19079ed697316
0x5585d30d68b0: 0xbc536181830cca25      0xc9f075e0a2b969a7
0x5585d30d68c0: 0x07ff26ac99eec295      0xb89c6edad840bfbd
0x5585d30d68d0: 0x2301529eda76231b      0x9f2fda2ecba25d7a
0x5585d30d68e0: 0x0273b6f821c4fb15      0x3434d6808fc4305e
0x5585d30d68f0: 0x1beb15756c5dabe6      0x98773ae7cb71b7f3
0x5585d30d6900: 0xa1cf84b7690a1501      0x1656d52c35b94017
0x5585d30d6910: 0x9899aa4941830fd2      0x6483c0b35b605ea2
0x5585d30d6920: 0xb32f5ced44f05c8a      0x4293a60fcfa4fb8c
0x5585d30d6930: 0xc35988a18602165d      0xffa29a2675e86342
0x5585d30d6940: 0x8b4fb263fe931625      0xb5b19366aa1af1bd
0x5585d30d6950: 0x26b4a3409857d407      0xd8c4898568739bb2
0x5585d30d6960: 0x5b1f2aa8cdbbb4ba      0x5eb85a95139595ad
0x5585d30d6970: 0x87e97ca15344db9a      0xd9f6b82a5b455447
0x5585d30d6980: 0xae9c1c2d16640275      0x7674d98423c5537b
0x5585d30d6990: 0x52aed1b2d4defa45      0xfdaeca9c34ccae1e
0x5585d30d69a0: 0xfbe766e867c90b3d      0x9268e2b69bd1fa1d
0x5585d30d69b0: 0x6871dd568c9efb5c      0xa349568e4144b8ce
0x5585d30d69c0: 0x0342b4aea3f0c04e      0xbe4e7776e4d690c2
0x5585d30d69d0: 0x6d181814ba5ebde3      0xec675ed35983a236
0x5585d30d69e0: 0x2592774b525a09f3      0x73fd264954fd0d14
0x5585d30d69f0: 0xdd71090d50d81f2f      0xd3b44ae76c5d4b20
0x5585d30d6a00: 0xe1fa2e787feffc34      0x799a3be1f7f06fd0
0x5585d30d6a10: 0xb71b21165cd41d7a      0x7025e8f95a39ce98
0x5585d30d6a20: 0x18163349b329cd4f      0x556ccb952f90b73c
0x5585d30d6a30: 0xc4ad70881435014f      0x1e1589046eaecbd7
0x5585d30d6a40: 0x14e47fc9e0eb1c78      0x646a1c01aa03aee5
0x5585d30d6a50: 0xfe7c34f925bd7cc9      0x03cf2e864a7255b5
0x5585d30d6a60: 0x08dcd26854a1ff18      0x73d91730df58afd1
0x5585d30d6a70: 0x3e7bf01181dbface      0x4a6ff0a35500841b
0x5585d30d6a80: 0x2d268088d912c70f      0xfbf19b4c9a59aeb4
0x5585d30d6a90: 0xf83a029f6c67eadc      0x7bd059fb96dc3e70
0x5585d30d6aa0: 0x9f44f21d5e4fcd81      0x3262161e367abe9e
0x5585d30d6ab0: 0xdcaf4eebfdf991cd      0x60139350df17f71b
0x5585d30d6ac0: 0xeeaee2f646750ac7      0x7988f32cafd042a6
0x5585d30d6ad0: 0xdfdea25fe788f57a      0xe6311145a205adca
0x5585d30d6ae0: 0xf69585d4ff57d5eb      0x59b0d4bd37c714f3
0x5585d30d6af0: 0xd4fc243a12d7ed45      0xa9b0d6052ec832c7
0x5585d30d6b00: 0xee451714babc74a3      0x49a86dbe4fb8300a
0x5585d30d6b10: 0xfd8223d4aa3319df      0x3497a4da8efafb1e
0x5585d30d6b20: 0x89bbbac99d33cb12      0xde223ee900cf724e
0x5585d30d6b30: 0x4f3bfb6682ca2464      0x19ff46983fd4f473
0x5585d30d6b40: 0xff108f07eb035886      0x65941c3c3ba2b79f
0x5585d30d6b50: 0x7b9675a14b4299b3      0x3a9336666fc23424
0x5585d30d6b60: 0x69ac9c2e8ad88cbd      0x2f7b91719a5e6cb7
0x5585d30d6b70: 0x82f5d0749d1a7a25      0xab6c7ef6cb2006ae
0x5585d30d6b80: 0x685d832c6b0fae9f      0x51fc47996646bb9d
0x5585d30d6b90: 0xbcfbe85a1296b122      0x95e915456c8fcfd0
0x5585d30d6ba0: 0xb0678fc1e7c66e6a      0xe22aaef0a101c0a5
0x5585d30d6bb0: 0x4c696cad7775b912      0x95e1276f342322c6
0x5585d30d6bc0: 0xbb76b5a80cf4c24f      0x83610d7a1bb00bb1
0x5585d30d6bd0: 0x65fd131405d0bc0f      0xdb1ed2551e69db15
0x5585d30d6be0: 0x55b3296b93d6b60d      0xaaacd29ea9374b9b
0x5585d30d6bf0: 0xc64b6ca617dcabdf      0x8e6b521f068b5b4e
0x5585d30d6c00: 0xb2f1fa5056c07902      0x625f3c81c3116ba3
0x5585d30d6c10: 0x3fd7ae531efe6785      0xf0784ab158c1add4
0x5585d30d6c20: 0xfb43bf433c1b662f      0x2e8b994d599b09d6
0x5585d30d6c30: 0x3450bf04da1cf092      0x23636ec57aa38bae
0x5585d30d6c40: 0xe29e4be5547ab4f5      0x37a354f2a11e5b27
0x5585d30d6c50: 0xa70490f02e39d7e9      0x150df6f17015e335
0x5585d30d6c60: 0x70936096818cbc38      0xd8b6e54be7790c30
0x5585d30d6c70: 0xee7aebe9464065a0      0x40e18cd34d5d1b58
0x5585d30d6c80: 0xf712d6fb3175b79f      0x624b5ae01b9ce875
0x5585d30d6c90: 0x84da2036f4349213      0x96ebe0ad714064d0
0x5585d30d6ca0: 0x0d60b62f9e268774      0x4a8d3d297721fdad
0x5585d30d6cb0: 0xf27f16afc37347a7      0xff28addf6bd429f5
0x5585d30d6cc0: 0xba4707c7392748b8      0x4b3c8771d4bd8d41
0x5585d30d6cd0: 0x97a19aa230f2d41f      0x85d2a74e69e3ffe0
0x5585d30d6ce0: 0xa2e03f3fce50ff17      0x8f00c3a38565c267
0x5585d30d6cf0: 0xbdaf1c9565fa0b85      0xeb94a4ae776d5d14
0x5585d30d6d00: 0x01166b424549cce4      0x472b82207d42ae61
0x5585d30d6d10: 0x549df42e7d7a0c5c      0x53ac06aef3d1162c
0x5585d30d6d20: 0x84f975914dcf2486      0x3a8ac4ddbc47a6a7
0x5585d30d6d30: 0xdc8740b48faa1c0d      0xac1a9bf106fc8fec
0x5585d30d6d40: 0xbdddea4fe53f6d60      0x70bd044f5d87648a
0x5585d30d6d50: 0xaa7818b471367e2b      0x0d72ae1b907615ce
0x5585d30d6d60: 0x9a96e3662157be66      0xe4b91a1f32a4b5e9
0x5585d30d6d70: 0x611e5e5ce6098055      0xdb7c79fde092492a
0x5585d30d6d80: 0x1e67532785aa8d0b      0x9031643d97475f9c
0x5585d30d6d90: 0x15222cca50931446      0x969acef283f4f321
0x5585d30d6da0: 0xb1b1a3ecbfea2906      0x022b83e84b113768
0x5585d30d6db0: 0x123911a422222ceb      0x903ae29b4097f3bd
0x5585d30d6dc0: 0x6ff62d88101ffceb      0x77fccb572c9421c5
0x5585d30d6dd0: 0x035e2d3278208437      0x5f339e2561339ceb
0x5585d30d6de0: 0x829cf80b16e54dbd      0xa75e3647adbc59da
0x5585d30d6df0: 0xffebc39d8f24eb3b      0x9435b06f9f36fcfd
0x5585d30d6e00: 0xaafe060acb970990      0x853fbba7556c2079
0x5585d30d6e10: 0x716ea0f35c41d1aa      0x4a1e9e271739f714
0x5585d30d6e20: 0x68a5faece94b1edd      0xc7320720ef3d8ca2
0x5585d30d6e30: 0xb19162024814259f      0x32e65bf7183b99f3
0x5585d30d6e40: 0x038f2ad6dfafda1e      0x043f201ff0dcd4a4
0x5585d30d6e50: 0xc554c27c1716be67      0x58bb438bdb47e148
0x5585d30d6e60: 0x9b31f4fd652050c5      0x79305238e844535d
0x5585d30d6e70: 0x4ab6b5b5ec6f102f      0xca986805c8a8160c
0x5585d30d6e80: 0xc4591e8c3a3533c7      0x8641741ea93d0f1a
0x5585d30d6e90: 0x0212bd6b4395e74a      0x379c8cb6a19c72be
0x5585d30d6ea0: 0x360c022a3d2382a1      0x7d06a1b5e0dc0b0e
0x5585d30d6eb0: 0x94dcbaa15584760b      0x4111c3e2228d732e
0x5585d30d6ec0: 0xac0e830b449d05e1      0x18af46b96dfa3dfc
0x5585d30d6ed0: 0xefb22ab310534896      0x7a94671cd5f65d9c
0x5585d30d6ee0: 0xb3b883617ee39601      0x218738ef80571901
0x5585d30d6ef0: 0xc06c9cc52010b3bd      0x240ba7bb99a36aad
0x5585d30d6f00: 0xacd97aed9bcea7cd      0x9bfd0dbea11abd81
0x5585d30d6f10: 0xa73cfc3ee8a43d4e      0x81f6dbf4426c50d2
0x5585d30d6f20: 0x97e19efc58b52b4b      0x7203eef1a5d2767a
0x5585d30d6f30: 0xc6a0a0c536810c7e      0x10da6e18216e6137
0x5585d30d6f40: 0xd8657441c474b838      0xe6850cb7c5474ecb
0x5585d30d6f50: 0xe99e977077c8eb94      0xe56bad6e02ca81b2
0x5585d30d6f60: 0x78569b2e1532fac1      0x1e1793e1da6af3d6
0x5585d30d6f70: 0x7ca30656cb63b3b5      0xc1d2819ba299cc78
0x5585d30d6f80: 0x7a992e0a6f55d2d9      0xaad7fe64a09bddcc
0x5585d30d6f90: 0x31c58dd0dfbf232e      0xc48a86227314e9c9
0x5585d30d6fa0: 0xbb00353e4d64a607      0xf68c9f45f3128896
0x5585d30d6fb0: 0x95498a0db3057e39      0xa7dae550fdf9b762
0x5585d30d6fc0: 0xa719a6f703d1b5ea      0xf752075dad8114fc
0x5585d30d6fd0: 0x3eedc0ec4f154d28      0x6a57c2be55ea0be9
0x5585d30d6fe0: 0xa44d6091da52478d      0x3c128e42be244ef4
0x5585d30d6ff0: 0x037539baf37a4763      0x34cf58c49a19afe3
0x5585d30d7000: 0x1b77ee75922a5570      0xd431f58f91dfa44f
0x5585d30d7010: 0x20db26226e8a1b4d      0x61dda96978c77bc1
0x5585d30d7020: 0x3f724e049902f7e9      0xb224a2489f6030bc
0x5585d30d7030: 0xfca0937387840475      0x2ac9ae469395554e
0x5585d30d7040: 0x41ca993c20cafd30      0x2b166a3f52688929
0x5585d30d7050: 0x0b09258bfc9cb06f      0x12dcf454c2014189
0x5585d30d7060: 0xc295f0eea2e5f87c      0x8cbe4dc26be09bda
0x5585d30d7070: 0xa8bfc5e1f9f5f8c5      0x225f044dd4d0dab6
0x5585d30d7080: 0x2d091bea460a1f34      0xcd06a0e3a855c320
0x5585d30d7090: 0xec546e41464b6dc6      0xb9f70cecc139e210
0x5585d30d70a0: 0x4c51b89262485995      0xa7c0339c5ddeee4b
0x5585d30d70b0: 0x4e8181b065622a28      0x5950e9a9e0a24f9a
0x5585d30d70c0: 0xa804f8b03c887058      0xac9789745ea97706
0x5585d30d70d0: 0xaad8eefe251b08a9      0x66f41f31da5aa694
0x5585d30d70e0: 0x95a0741afb04b0bd      0x8aa6e89f08cff9f4
0x5585d30d70f0: 0xbd4da54756dc5ea8      0xaa2b2ff9fe85d731
0x5585d30d7100: 0xdc9bc362e3fffb40      0xea3026164ae755ee
0x5585d30d7110: 0x96deaef04db27e6e      0x1a98ae0d93e0fcfd
0x5585d30d7120: 0x0b39358a42022015      0x59e6dbe99401985d
0x5585d30d7130: 0x920b2e0c13f30e22      0x2f6081f496947ad1
0x5585d30d7140: 0x4b2094d60a808b59      0x182c1c0f0d50b2d3
0x5585d30d7150: 0x2cae8e3132ef9a1a      0x4f94e0ee77212fa0
0x5585d30d7160: 0x524a6b8728c7999a      0x0b52fd2fb06f20e4
0x5585d30d7170: 0xb7c3dd846a48ab92      0x118d87c1fd9a33b5
0x5585d30d7180: 0x7e045b362ce650a8      0x41c5ac15c7ec9d86
0x5585d30d7190: 0xddf5be09ca10a4ef      0xc95e9726cfffe84b
0x5585d30d71a0: 0xf19af70d3ce00e27      0x48e54304dbd1f521
0x5585d30d71b0: 0x362840c4ccbec293      0x0d9dc66246c4d0f1
0x5585d30d71c0: 0x53494d36e69da96d      0x8ca1b7d869096828
0x5585d30d71d0: 0x33a346e3dd616a50      0xb00ef385a0e61247
0x5585d30d71e0: 0xad953c39ac7eb39f      0x5f5e566bc8162270
0x5585d30d71f0: 0xc9d6d90e7d1b7c56      0xa624a27f1bfa0c92
0x5585d30d7200: 0x7abedec817bccf5f      0x6fe399d579716080
0x5585d30d7210: 0x0c5e6963163af550      0xdeab28eb7f6bd5a9
0x5585d30d7220: 0xa9b5fbb832822b00      0x3007f58987b53cc7
0x5585d30d7230: 0xb98f13940052fa01      0xdbe3acb3d04798fe
0x5585d30d7240: 0x220b1774c21f5e4d      0x7c67f4527ce519ed
0x5585d30d7250: 0x71a263d570ebb039      0xc7988decb34a5702
0x5585d30d7260: 0x215b4e13e7ffba18      0x89d58517f2bc09ad
0x5585d30d7270: 0x161cb555018f7d7a      0x6ed62d057b811661
0x5585d30d7280: 0xcded55f8740ee7f6      0xcca5fdb58be59e80
0x5585d30d7290: 0xab582e1d09547682      0x5d0781c6815670f7
0x5585d30d72a0: 0x2a0a2c9e88e70cdb      0x18fb16b67ae6ce2f
0x5585d30d72b0: 0xf1f8b63e207b0faf      0xcd3de921761bef6c
0x5585d30d72c0: 0x78b7198432f3b364      0x0673d10f155ae2a1
0x5585d30d72d0: 0x5d9bf36021c54e50      0x5df0a092a54606cf
0x5585d30d72e0: 0x7d59bd32cdc1186c      0x636324bcdacc5481
0x5585d30d72f0: 0xb43273b99ace42eb      0xa74d042925f1cf36
0x5585d30d7300: 0x6c887080634ea59d      0xa3d8050c04e216af
0x5585d30d7310: 0x95b59af872a9a619      0x8da0797623b211ce
0x5585d30d7320: 0x011b4aca49a67485      0xd9d0ca4aead11049
0x5585d30d7330: 0xc6b8e71adcdb78b3      0xee818eefd98e5c67
0x5585d30d7340: 0x7e0504db73ad4460      0x49c034be124282b9
0x5585d30d7350: 0x27b054994653e34f      0xe3be4ca8fef017a7
0x5585d30d7360: 0x7f39cfcca0d1d7b8      0xfcbf6d7655c3ab1a
0x5585d30d7370: 0x79c9fea2976a64e2      0x6fd9a5bd262dcefd
0x5585d30d7380: 0xf5a3e3277f88632b      0xd764de943667d08e
0x5585d30d7390: 0x50e980249d7d68b6      0x8b1d27e9b32096f0
0x5585d30d73a0: 0xddadda23dcd77241      0x05ea606d0d462b33
0x5585d30d73b0: 0xe8d7b1c1260f26ad      0xdca14ae7413232b3
0x5585d30d73c0: 0x6931f6e45a7a98da      0x7f1faf2e96c1eae7
0x5585d30d73d0: 0x1d9cf18e6b580bde      0x05e79a10416ee0aa
0x5585d30d73e0: 0x18d8730753860fbd      0x4e4a65696ab04b51
0x5585d30d73f0: 0xf039bd644861c585      0xd44a2c27bc30f2e6
0x5585d30d7400: 0x505a0f04c9f96deb      0xb3163513ff9574b5
0x5585d30d7410: 0x2bde1c5241cb223c      0x2f91659821b2890f
0x5585d30d7420: 0xd60a915fdfd9c2f4      0x022764c23377fbd6
0x5585d30d7430: 0xe4afc7cf57ce647f      0x691f93881adb0a1c
0x5585d30d7440: 0x924b8e16d3dc1647      0xca7c18e125215b4c
0x5585d30d7450: 0xcae08c91ce53f353      0xf41f65a9856e0b70
0x5585d30d7460: 0x4b66bf868f660d9b      0x49b4ce8320a82291
0x5585d30d7470: 0xdb51974b19783998      0x82d77feda292b6bf
0x5585d30d7480: 0x7abe5ad08aca63a6      0xa8b3f6c2ffb8833a
0x5585d30d7490: 0x83d2da78b064c2cc      0x365c9b251c105fbf
0x5585d30d74a0: 0x368ca8cc4e7cb8f5      0x42fb5ceb1f33407c
0x5585d30d74b0: 0xb12b7f14fb00358b      0xdaecd9a40a8323dd
0x5585d30d74c0: 0x21c7f5f6cfbdca29      0x5ec091b40be984d5
0x5585d30d74d0: 0x26c1e34b41bc924d      0xf95886fdd2769916
0x5585d30d74e0: 0xf1e938c4ffcf0609      0x089207ac0b3a36a1
0x5585d30d74f0: 0xa1c3ba157e022036      0x75a75c5a21714cc8
0x5585d30d7500: 0xb17821b9c73375e0      0xaeeee0b6b8cc14bc
0x5585d30d7510: 0x66d40abef9813489      0x37136654c827187e
0x5585d30d7520: 0x24f8f782bc6ae4db      0x860075d0df9f8620
0x5585d30d7530: 0x0bbe85f957f7d478      0x3fb2bf9abfee9a9a
0x5585d30d7540: 0xf48c11ebdcd6a91b      0x44e31abaace7d34a
0x5585d30d7550: 0x1f8ad3bcc0b6dc47      0x93fbf08abd615b30
0x5585d30d7560: 0x8cab64badd83f69f      0x2009dcd3ddad359f
0x5585d30d7570: 0xea3580f663725a5f      0x4a4b23bad9fa422b
0x5585d30d7580: 0x895ddd3cd0175cac      0x7b8c14ae33673c98
0x5585d30d7590: 0x78acd2cf6283d000      0x008df509173f694d
0x5585d30d75a0: 0x927948387d659591      0x12b2e62dbfb2bad9
0x5585d30d75b0: 0x60c89c5e6d2ddcbf      0xc5296eb4a49bd1f8
0x5585d30d75c0: 0x91b6c17522d52de0      0xd51e82482102b1d3
0x5585d30d75d0: 0xb24ba41c3482d409      0xe6285df3b1dc5158
0x5585d30d75e0: 0xd1b3d1bee74654e2      0x8ac9b529d54b159c
0x5585d30d75f0: 0x7937288b753896ab      0x5b81ddfc4d1a3306
0x5585d30d7600: 0xbfe57b1fb75d37d8      0x10616e9f00c757b1
0x5585d30d7610: 0x38fc869a03c5f073      0x3a94f7572c4c2d77
0x5585d30d7620: 0x55727a9a6f5bbd7f      0xc70655f0d2594534
0x5585d30d7630: 0x4ffc959a3d6b8284      0x6a4f4b7f250ad539
0x5585d30d7640: 0x23bbc1e525ec7b1f      0x034d7adeeacde7b7
0x5585d30d7650: 0x353ccee63716919c      0x472464fcba1f220b
0x5585d30d7660: 0xb92867d1e027dd0d      0xaf8a5947793624db
0x5585d30d7670: 0x45ced7db7c24772a      0x553547aeb6c2cc56
0x5585d30d7680: 0x753206c456cd9273      0xba102fd5363e0465
0x5585d30d7690: 0x2cc84f6c1ac24d2c      0x682a7258cc96501a
0x5585d30d76a0: 0xdd75540176cefb11      0x4147eb586d1df25b
0x5585d30d76b0: 0x389b53b29922b430      0x3e8e76d2b63042c7
0x5585d30d76c0: 0xd4976f86f7a74763      0x6280c1727232aa9c
0x5585d30d76d0: 0x2be4a16f170a4012      0x0a45ed3ac758f7bf
0x5585d30d76e0: 0x1788aaee50e8816a      0x6e20523a249d9935
0x5585d30d76f0: 0x1b7fa739ef59bc95      0xb5949eaaa5338bd7
0x5585d30d7700: 0x8a7db30b3baa6579      0xa48fe4b760670709
0x5585d30d7710: 0x5c6a9104bc0914e0      0xd5369ca4c1daf066
0x5585d30d7720: 0x7a610e38a5b606ad      0xb2a6756ea0bc9ff2
0x5585d30d7730: 0x939d349554bb9492      0xe25c182658f66bb8
0x5585d30d7740: 0xc3aeb5c189127449      0xabc58fa8af0ce53a
0x5585d30d7750: 0x631d4b0c56c98010      0x1442facbf787686a
0x5585d30d7760: 0xb96c19686cc46fe0      0xe595cd143c8b8ada
0x5585d30d7770: 0xc629441af4bed0f8      0xeaa18394bcf73363
0x5585d30d7780: 0x6c9e9eb68b487d4c      0xf19b8f081be82e74
0x5585d30d7790: 0x4cbb1483a1454f45      0xd95e6e0c5e4c5bb8
0x5585d30d77a0: 0x2718c0bcd34b702b      0x2418f234e9067028
0x5585d30d77b0: 0x8c239984720a94b9      0x865a2ad0f89df66e
0x5585d30d77c0: 0x94e5909d8ea06077      0x44c625873123fb3a
0x5585d30d77d0: 0x917284136e913e0c      0x66bd1e0ab7eb3212
0x5585d30d77e0: 0x58f8697e92e0b3dd      0x50468b9e8c700eb2
0x5585d30d77f0: 0x58bd4ef7dda0322b      0xf3d18e6cc71c58cd
0x5585d30d7800: 0x33486d50dfcdd9b2      0x6b7afe545e83bfb1
0x5585d30d7810: 0x7858fe38b120528c      0x2d6db470eabcda20
0x5585d30d7820: 0x07136ca43f941053      0x30c16d784f47bdd8
0x5585d30d7830: 0x3edcf45d9fcd61b1      0xd3781aac20484c57
0x5585d30d7840: 0x896fa92e3e3629fe      0x48ee1b267cea8f15
0x5585d30d7850: 0xd2a268959cd21bd0      0x293f513317861a8e
0x5585d30d7860: 0xe7c132d4bb4ba850      0xbff4fc8dff41fba0
0x5585d30d7870: 0xcffad190ab7bae7e      0x92e544408994642a
0x5585d30d7880: 0xe31e2d3f842d6354      0xa49d8ac472c56034
0x5585d30d7890: 0xff091d0921ba75b1      0x7e4d97b39c0c597f
0x5585d30d78a0: 0x7a3b06ea1ff19ba6      0xed33edb7a3e2c5b6
0x5585d30d78b0: 0xcb62112af529069a      0xbde78b73ce57062d
0x5585d30d78c0: 0x519b3eae42c9009d      0xd1dfd647c10b194e
0x5585d30d78d0: 0xfc9215693fb496ef      0xf1176179a4e6494c
0x5585d30d78e0: 0x1653a66fe8f31c37      0x27a960b9657dfab0
0x5585d30d78f0: 0x5ddbecead3bd7232      0xb227353627ea0aa1
0x5585d30d7900: 0x95604e5ba0009dd7      0x02fe5d676b405ed0
0x5585d30d7910: 0xff046bb625c88e07      0xb69e9bda1f9d9ab5
0x5585d30d7920: 0x75c4b80a8dcde62f      0xa4625b22fa4761b4
0x5585d30d7930: 0xaa8aced6c840073d      0x3325599d96a09b1a
0x5585d30d7940: 0x49c48d0e485bc2ff      0xca474c926986e951
0x5585d30d7950: 0x458c0bf4f7c0a90b      0x8916794a066d643a
0x5585d30d7960: 0x62666a8d82ae75ae      0x7242b9edd38dec75
0x5585d30d7970: 0xd609b3cba39f222e      0xe0c02b600411c082
0x5585d30d7980: 0x585f158e59cdd841      0xac2fe3bec00c306b
0x5585d30d7990: 0x15e85242fe679a16      0xe370ce4123bbc592
0x5585d30d79a0: 0xac300e56467598a7      0x040460b5debaa963
0x5585d30d79b0: 0x32053236da1e20d1      0x626ab524291cdb43
0x5585d30d79c0: 0x2da3fd5ffa6e2b32      0x34bc80682695f5e5
0x5585d30d79d0: 0xd1ebc38bbe3c0b84      0x5a4a7225c139d2de
0x5585d30d79e0: 0x3ad93e2143da64d4      0x671a4f5eac099ad7
0x5585d30d79f0: 0xdcb3212691a2c579      0x1461cc3908c05d24
0x5585d30d7a00: 0x5043be5d4cda0b93      0xf2628823db455f4c
0x5585d30d7a10: 0x6c015c8c705f1f24      0x1da5e910ce778db6
0x5585d30d7a20: 0xcf9f4a0bf80629b7      0xc075304498e135a9
0x5585d30d7a30: 0xb0f80e00ac8b49b8      0xef056ef618f9f4e0
0x5585d30d7a40: 0x3d1df47feda9b972      0x4b9d4c88341076b8
0x5585d30d7a50: 0x94c72d703bcfb4de      0x4df697053249d127
0x5585d30d7a60: 0x2ac2d524f3bf266e      0x9ff286ecf2949355
0x5585d30d7a70: 0xee197c15f5afb698      0x4ee20a22f43cb932
0x5585d30d7a80: 0xe8a2db73200dcec7      0x8260d7ad8d7f1626
0x5585d30d7a90: 0x8f17ca5f24a37ad0      0x0e2ee3e1bf0587df
0x5585d30d7aa0: 0x2fcb4f93737b8d1f      0x7190225953c1eaa3
0x5585d30d7ab0: 0x32e0bba24b3715e3      0x7ec745425cd50654
0x5585d30d7ac0: 0xe1fc47ccadda4222      0x3aa1ba23f29b7d8e
0x5585d30d7ad0: 0x1a0ea6d1708c9eb5      0x0a4c446b7f706cc2
0x5585d30d7ae0: 0x071bb89e51131356      0xe91b628228e4288e
0x5585d30d7af0: 0x9f277f8d519727d8      0xe409276f9aa348ea
0x5585d30d7b00: 0x4ce2722d221ad3fe      0xf95b778e5c5c23ca
0x5585d30d7b10: 0x4931250905742e10      0x27a49d811f1b899a
0x5585d30d7b20: 0xe6afae519ccb5a64      0xa2e0ab1050444216
0x5585d30d7b30: 0x6863a1b78fc01599      0xad3dffd793d54c15
0x5585d30d7b40: 0x5db121066682e18a      0x1069181b91abf3b9
0x5585d30d7b50: 0x61a3dcc22e4d2a37      0xfcb81b41b5f2efcf
0x5585d30d7b60: 0x80302f273be67f81      0x55c5381c19aeba58
0x5585d30d7b70: 0xb88cb7caea75a1fe      0x1cadee6e9c7897b7
0x5585d30d7b80: 0xf2dc4ca879f81c59      0x487c35f7150ac23f
0x5585d30d7b90: 0xa6ad1a5d48e156ec      0x46a48c0550503946
0x5585d30d7ba0: 0xed966707f3d7efc2      0x53d821d94c1bad42
0x5585d30d7bb0: 0x9ba74855b1bec10c      0x164decf29bec101c
0x5585d30d7bc0: 0xe2010d16481e4f00      0x33c912050e5d0c5c
0x5585d30d7bd0: 0x44aaca88c429ac01      0x8071e1b326da63bc
0x5585d30d7be0: 0x39ce52e7e992fa9f      0x45083f606ecd7725
0x5585d30d7bf0: 0xee53c69427e79209      0x08dd7f65c40c8097
0x5585d30d7c00: 0x4d056fdcfeecec9a      0xd9f130ce3ab2b1d7
0x5585d30d7c10: 0x02dbc8a178fac257      0x898daa77ef1ad70f
0x5585d30d7c20: 0x8b829443e9facd99      0x01bff0aae8e6af1f
0x5585d30d7c30: 0x0863d6579ec11dec      0xfc7382fb4ef4d8c1
0x5585d30d7c40: 0x416f321ee9325ea7      0x1107e8de08394968
0x5585d30d7c50: 0xd08acf204fcf44b1      0xfd6d1ea0ef7b0c67
0x5585d30d7c60: 0x2ff6da8dbeca739e      0xd7ce10e5af500a1e
0x5585d30d7c70: 0x9e37ba3e32ea2bae      0x8ae414023570486e
0x5585d30d7c80: 0x5c5e21d3edcc21c8      0xc6f2f558f4a7a113
0x5585d30d7c90: 0xe562ca0e2468436a      0xcd8880ce78fdbc71
0x5585d30d7ca0: 0x64a9e97c79038eaf      0x8fa11acf790898b6
0x5585d30d7cb0: 0xfa9712822e1f92f5      0x0be0a47e7c33794a
0x5585d30d7cc0: 0x0f513f6dfa219683      0x7882a2fd7ad96f95
0x5585d30d7cd0: 0x724103437a884352      0x38856f600ee9c153
0x5585d30d7ce0: 0x34844c1c042e4031      0xa25072078f86d4b0
0x5585d30d7cf0: 0x198ebf757f3ce869      0xc19a41f94296d3f4
0x5585d30d7d00: 0x15253a9cd3916853      0x4e63ded01c521c71
0x5585d30d7d10: 0xdd7320b7e2575f4c      0x27a5680626ba3a3b
0x5585d30d7d20: 0x22126f89ee83b6aa      0x93ba54007bb31b86
0x5585d30d7d30: 0x9223523b754a6398      0x41e09449d7b89bf9
0x5585d30d7d40: 0xc88439c35bf3c9c0      0x3f2c59b8c9819aa8
0x5585d30d7d50: 0x131cbfa7b1a189cd      0xb65edcd66c1bc99f
0x5585d30d7d60: 0xf47c981edad2f0cb      0xdf8d4d2c96ddbeaa
0x5585d30d7d70: 0x18574111ff0734ba      0xd0e93b5438cd4afc
0x5585d30d7d80: 0x10d43fd61bdb8f22      0x738cf2854d70f45d
0x5585d30d7d90: 0x0c674b0d4e824ddf      0x7038a38b2d798915
0x5585d30d7da0: 0x32b6526eccbfdc96      0x180c079be4ac34e5
0x5585d30d7db0: 0xc176bb77b22141d0      0xff21c2ae147d4f6a
0x5585d30d7dc0: 0x8b40d6bdc6539848      0x697c85f228d8efe8
0x5585d30d7dd0: 0x33b66e95c3ed31cf      0x1efd0b3d9134086b
0x5585d30d7de0: 0x57f12eab85d92859      0xd3245da1f30da714
0x5585d30d7df0: 0x9240e371486eba6a      0x01f700f3d54de9ef
0x5585d30d7e00: 0x8a808614211c71a2      0x58c4d221bea647f7
0x5585d30d7e10: 0xe3fa18751da412b9      0xd2c8a94ac4fbf865
0x5585d30d7e20: 0x5391d799d97952c7      0x99401c7c531de610
0x5585d30d7e30: 0xe21205f95344dc74      0x9f5cd417a6c932d5
0x5585d30d7e40: 0x454af2c839aba3ec      0xdb874569a41f63c8
0x5585d30d7e50: 0xb132e85219026d4c      0x914987fd87bfa10f
0x5585d30d7e60: 0xd85443ea0d384fd5      0xaee9f5bc343a2cb0
0x5585d30d7e70: 0xdfdcafdfb073856d      0x87a720c53d6cb449
0x5585d30d7e80: 0xf1fcbb192e47a7e9      0x6acc3444a6899a26
0x5585d30d7e90: 0xe5422a71e506487f      0x12f67f68a9287f7c
0x5585d30d7ea0: 0x69591c316466a675      0xb3dda204b95e95c5
0x5585d30d7eb0: 0xe0ea8a3644e502dc      0xb45fc87d020ca2df
0x5585d30d7ec0: 0x68d94bfb134e512f      0xef0ceeded204d647
0x5585d30d7ed0: 0x255880926e620233      0x81150acc3645cbbb
0x5585d30d7ee0: 0x1420578d995054c2      0x8d5c569f6912a050
0x5585d30d7ef0: 0x2aa8099da719ab76      0x187ee6a936e5b8a1
0x5585d30d7f00: 0xfef5bd49ff67bbe5      0x35be16580484e123
0x5585d30d7f10: 0x88e167bf8d8954e1      0x1f281cf3bb1b8f94
0x5585d30d7f20: 0x9cfeadc52bf7683d      0xe697c68b320b00f3
0x5585d30d7f30: 0xb49a9ee1014c880a      0x1d27e9b9e0cb95e0
0x5585d30d7f40: 0xb0c0ebe0643d666c      0xd043ab92caec666f
0x5585d30d7f50: 0xe78d9bb3e21509e2      0xaef674dab867dc5c
0x5585d30d7f60: 0x717239a68a8d6eca      0x84963a2cb56fb0b5
0x5585d30d7f70: 0xfec088b27b2983b4      0x66a1bc84321cf390
0x5585d30d7f80: 0x190e3d7ae3b183c9      0xcfba36ba02d139ae
0x5585d30d7f90: 0x21febf6acd388fb0      0x1050297a4c25e62f
0x5585d30d7fa0: 0xd87277a697909755      0x7dd5d0f353aaa9cd
0x5585d30d7fb0: 0x9f065a210b6dabb4      0x254519dc30782065
0x5585d30d7fc0: 0x5839d3e7fa3a5fa8      0xd0e5d4c427a5eb85
0x5585d30d7fd0: 0x7fc41886d9d97cd1      0x15abc186126a4dd8
0x5585d30d7fe0: 0xafe07fee732e1e78      0x11c1dcea5dd1ee48
0x5585d30d7ff0: 0xe6355800792cb2f7      0xd03e3f0c768b8981
0x5585d30d8000: 0x3dd3c7fafef577b0      0x8c6947a4f38ae315
0x5585d30d8010: 0xcda3d603ea9a2c55      0x9687e306e7c6f9cc
0x5585d30d8020: 0x311553926e580edf      0x7dadc6d4824b4109
0x5585d30d8030: 0xdf054e8c36ae5b4b      0xb59b19c580aed11d
0x5585d30d8040: 0x56176eb9b970b869      0x5b1187e521eb2e25
0x5585d30d8050: 0xfda241c8854f6e20      0xfa066cbc10e11b7d
0x5585d30d8060: 0x012eb95dfd73bcc7      0xb947a7b386ca41c2
0x5585d30d8070: 0x5edb248fae9f2949      0xf8aa78edba78ff77
0x5585d30d8080: 0xe0518c83acfe6856      0x4bb4514b0fae6b15
0x5585d30d8090: 0x200b16afeb6d1f5c      0xce46b789def043fe
0x5585d30d80a0: 0x3d86fc1622c79511      0x181777325cbbb0ae
0x5585d30d80b0: 0xc9e356b2c2a11f0c      0xba2bee9c1730fa35
0x5585d30d80c0: 0x597f198044a6b75e      0x9eef2f0b6f6d3515
0x5585d30d80d0: 0x464d678f4d750d27      0x5e19e83554f64bc1
0x5585d30d80e0: 0xf6556f3383b9d0e1      0x51ee49d6fcd057ae
0x5585d30d80f0: 0x2ac4b1dd650c2f11      0xa8eb62193e42bac8
0x5585d30d8100: 0x53d1927e12bd857a      0xa1ac241ba241a4a4
0x5585d30d8110: 0xa84c4379bf4fffbb      0x1696b001698c6568
0x5585d30d8120: 0xe16f273ef8303293      0xc32c77a05b0a24a8
0x5585d30d8130: 0x1365051799df7795      0xfb7f1ed32c9be6de
0x5585d30d8140: 0x6d6bc8a0ac72376c      0x66df7e581ae69a4c
0x5585d30d8150: 0x6e54926f40ed6141      0x592fc8c6a79cc1f7
0x5585d30d8160: 0x2ee42a4c99bfd51f      0x0fc54c034d871b0f
0x5585d30d8170: 0x3eb44e7f0d2b5202      0x155271d89fd82d79
0x5585d30d8180: 0x0038a271af152d68      0xfcfa563735ef5607
0x5585d30d8190: 0xf2ec405ba8f83da5      0x2b97e1aa248dbe21
0x5585d30d81a0: 0x9485147aeafdf41b      0x60d91e17572e4295
0x5585d30d81b0: 0x2794b129fc8db57b      0x3764b5790f142ad1
0x5585d30d81c0: 0x306b2a1fea7e7b57      0xa987405704922e71
0x5585d30d81d0: 0x49ce446b421999ea      0x5d70d72a98643390
0x5585d30d81e0: 0x3bd019d7537d91f5      0x1367f5c0e6dc9d4a
0x5585d30d81f0: 0x2e28dfd4585c4902      0x0fa74e98e4206a21
0x5585d30d8200: 0x3272fed7bd9b7bd3      0xebaef603231f0392
0x5585d30d8210: 0x1a425fb26e756a46      0x9d4b9acc47583e06
0x5585d30d8220: 0x56a184287df2578e      0x3e1c84f1d56dbabe
0x5585d30d8230: 0xce2649927140b807      0xaf34cad084d30660
0x5585d30d8240: 0x628e6d1091740ffa      0x6dd1891275b8633d
0x5585d30d8250: 0x517aef2ed6660c69      0x9239b567b502176e
0x5585d30d8260: 0xf9e4d8caa6da304c      0xc6122f1d0d4b73d6
0x5585d30d8270: 0x135ef7c95d073e48      0xfd86d03390d04393
0x5585d30d8280: 0xc7d14a80390bbf90      0x37046a41a3ccf236
0x5585d30d8290: 0xea1acc1444d3ab20      0x09eabdd48cc560f7
0x5585d30d82a0: 0x31c339584dd552d0      0x26a448852aa27422
0x5585d30d82b0: 0x3921e06f4bbbdfff      0x87269050ba0bf318
0x5585d30d82c0: 0x5d883bcfb5609be6      0x89fa7a715b125a2f
0x5585d30d82d0: 0x6c9339f1f11f200a      0x8ff853a27b30dd6c
0x5585d30d82e0: 0x1f10f3941de9048c      0xb3b207cffb85cf11
0x5585d30d82f0: 0x355cc1bd7a1cbeae      0xa902d8f833e553eb
0x5585d30d8300: 0xf5a6f1efbb64fdc3      0x26224710101a4703
0x5585d30d8310: 0x4d75cef87f1e1eac      0xa28160c4573a70a8
0x5585d30d8320: 0x31f8d1dbeffb2a5d      0xba0948dd5fe23ed9
0x5585d30d8330: 0x01ba314a41456a17      0x360445e880ef4205
0x5585d30d8340: 0x71e9a9e3b56a6cae      0xd8c2818296196aa9
0x5585d30d8350: 0x887ddff3ef02a94e      0xaa8749852295054f
0x5585d30d8360: 0x0236defbca0d6894      0x3c4a3bed9f8d1103
0x5585d30d8370: 0x86674921a8790830      0x618f0bdd70cc03a3
0x5585d30d8380: 0x612f034c4c31138a      0x9282af9638e202f9
0x5585d30d8390: 0xa20d0c4da7d79415      0x1cfc9752e3c5e7f8
0x5585d30d83a0: 0xe85b9d0ee80a4e05      0x0321a818a55e2719
0x5585d30d83b0: 0x4e36100c3ea67267      0xdc446344a8cf90b9
0x5585d30d83c0: 0x356f35fb8bdb32f9      0x8be8467b2e86d3de
0x5585d30d83d0: 0xa44f7cf911c6d230      0x736b56ef1733c293
0x5585d30d83e0: 0x2ab7f483cdedfedc      0x9264e6b7ed8719c4
0x5585d30d83f0: 0x21957be6d8f57213      0x1ae91942ba5f0a71
0x5585d30d8400: 0x8f77187b468576aa      0x285b3e32e4adea36
0x5585d30d8410: 0x827b1545621d7f6a      0x415d4b5fee62d41d
0x5585d30d8420: 0xacd3244ad5548419      0x4027d8018998d9b5
0x5585d30d8430: 0xa5240eef0c0758d3      0x7c859c7fb28168f8
0x5585d30d8440: 0x175bc6c6bdb4224f      0x84f55e9dd553f892
0x5585d30d8450: 0x451fa4bf96a7b757      0x25743d9a01ff6c94
0x5585d30d8460: 0xcfec25711ee5c2af      0x2fefc4f15aeeca8f
0x5585d30d8470: 0x7ac3070f984df4d6      0xffc7290b4ef16d3f
0x5585d30d8480: 0x0d14705fc53e92fa      0x262fc09d207032be
0x5585d30d8490: 0x838b24fa43eb0a8a      0x8fb858a57b845dff
0x5585d30d84a0: 0x720e94db4606e361      0x7d0dbe1fa3aad87c
0x5585d30d84b0: 0x35bcddd042f345d7      0x38b00e3bc6d16838
0x5585d30d84c0: 0xb9ce8d61b0f09e95      0x92a0192ecbdba086
0x5585d30d84d0: 0x6dcaa93d8e96ef74      0xe1fc008afd4e05e0
0x5585d30d84e0: 0xe74558490754adf5      0xf7461d0cc8e6cb23
0x5585d30d84f0: 0xa6260216daa5e197      0x50a27c1bb2010ae9
0x5585d30d8500: 0x1995aa01dea967b5      0xea253e8a58ac4ae9
0x5585d30d8510: 0xd9d806a7ac991b41      0x8307080c77c58b90
0x5585d30d8520: 0x3f35d35bbd04e201      0x7a20d044c68fc60a
0x5585d30d8530: 0x387734835ab5bca5      0xca97d5e7076f48a1
0x5585d30d8540: 0xe6cd1027d15c75ea      0x829c05f2b83b84cc
0x5585d30d8550: 0x0820b26e4710612c      0x5455efd93a8fd26d
0x5585d30d8560: 0x260768402bf5bc90      0x60ca21b1aa01558a
0x5585d30d8570: 0xdfe623f2c3ecf467      0xc8d4bc80e216d1d2
0x5585d30d8580: 0x78120d4b7205561d      0x192e1d1b61b16c9e
0x5585d30d8590: 0x240cec29cf6ac7a2      0x1428a1d98964d270
0x5585d30d85a0: 0x00e6e895421897a1      0xa75435ba290cbfbd
0x5585d30d85b0: 0x02c531951c8f37bb      0x9d6c00d4bbfb84a2
0x5585d30d85c0: 0x80b642d63c38fd17      0x5427b91833be6985
0x5585d30d85d0: 0x2b3a8066a2de199a      0x648d453ba639a1a0
0x5585d30d85e0: 0x162799261f96c3f7      0x756dbf4356298d94
0x5585d30d85f0: 0x5e97f32b9c18711a      0x841d59c60ff1d1e7
0x5585d30d8600: 0x0501fba5ea8e50c1      0x519977055381fe8c
0x5585d30d8610: 0xe7897beb52234c68      0x330fc14f7fc48244
0x5585d30d8620: 0xc99a2cccc7609160      0x77e60130457c8c4f
0x5585d30d8630: 0x448493d9e1b83cbd      0x9fb1100e6669b180
0x5585d30d8640: 0xe85667edb3b951e0      0xc777ece82e2f4072
0x5585d30d8650: 0xc20244c3a3d20564      0x34c91ff6363bb221
0x5585d30d8660: 0x6cf63e81d3dfe080      0x73573d5d2e364d29
0x5585d30d8670: 0xd8d24bb95ae8e88e      0xb34eb0338bc768da
0x5585d30d8680: 0xd5b4d62afe3710e6      0x51de453413b6d7de
0x5585d30d8690: 0xa3c2750d12cf831f      0x0b0e73325678840e
0x5585d30d86a0: 0x5f8273cad367fd99      0x701f937a45f1ada7
0x5585d30d86b0: 0x1a91b2f8f81f6763      0xfc9c15e2c53215f5
0x5585d30d86c0: 0x787981b1d3719ead      0x7f43d514f69cfbbe
0x5585d30d86d0: 0x09667a731d0b4bbe      0x8c1de1ed9b1652ee
0x5585d30d86e0: 0x7284a7dac2a1f4cc      0x8d478255340ac16e
0x5585d30d86f0: 0x76975f954613d750      0x2b4bcfcddde7a057
0x5585d30d8700: 0x77d78d02ce684b13      0xea84baac43f68f8e
0x5585d30d8710: 0x55ff53454bde05f2      0x63505ca5d77d3381
0x5585d30d8720: 0xbac62381abde1180      0xd6f63eb1c6dc174b
0x5585d30d8730: 0x573756dd4a632ff3      0xe2d5949ee4d54fc5
0x5585d30d8740: 0x13e7097135e67f62      0x0c08fb459b93ca7b
0x5585d30d8750: 0x7fd2f47f9e7f65b1      0xa6df78c66e062926
0x5585d30d8760: 0x29cd97d668e438fd      0xfe5321daf7bd40ab
0x5585d30d8770: 0x96fad01bb60e8276      0x6a6811db19500f36
0x5585d30d8780: 0xc1f257fd73ed5a85      0x907ee524e8ac0316
0x5585d30d8790: 0x4eece4f5d0c72a0e      0x58cb3ee3c63e3871
0x5585d30d87a0: 0xf21552bfd854cc3f      0xdbf29ed73810187c
0x5585d30d87b0: 0xbcc2efc1a6ab09a2      0xb17b1e8466c80aa0
0x5585d30d87c0: 0xd389ae6ddd0478f8      0xb632d3de5b688b66
0x5585d30d87d0: 0x050d8333fd338914      0xf6efa5fcdfc5712f
0x5585d30d87e0: 0x7b3fab6793953809      0xdc9800da56566dcc
0x5585d30d87f0: 0x084cd939aa3ba2bc      0xfba0b9f2ce19c7b5
0x5585d30d8800: 0x17ba99c1365956bf      0xfd07dea8d814aa59
0x5585d30d8810: 0x23430f8843d071ee      0x1aa318e61cbb5c1b
0x5585d30d8820: 0x658e6efe969c4ea2      0x2ec719fae66abc61
0x5585d30d8830: 0x7760f8f57212cb2d      0x1dc5620b761feffc
0x5585d30d8840: 0xe8c5edc5b96f2372      0x1347e8204cad079d
0x5585d30d8850: 0x05934e0212402596      0x46d8c153ba7c8929
0x5585d30d8860: 0xe876d14e3a3d1c45      0x23204ec134817d85
0x5585d30d8870: 0x9b5cd4ed8cbce369      0x46d37d6d16e5b47a
0x5585d30d8880: 0x2df6db5d02826d54      0xa5e89b3899dd6079
0x5585d30d8890: 0x5d066a574cd5dfa3      0xc303e664810e6741
0x5585d30d88a0: 0xd3bd309be31050e1      0xb31eb4063f9506f8
0x5585d30d88b0: 0xb2b10af4d2d51b94      0xf1c0914a473e6651
0x5585d30d88c0: 0x98a1639d184ae68f      0xda3b2fde51b7efae
0x5585d30d88d0: 0x6659ac01c03b28a9      0xa0b1c7c6aa3ca86e
0x5585d30d88e0: 0xce8956bc7c1afd80      0xe8c3f3d46ce85bc1
0x5585d30d88f0: 0xe414c51fa25a0500      0xd814ef489c746141
0x5585d30d8900: 0xea1bc065db48f012      0x565e493f7cfb0cd0
0x5585d30d8910: 0x2b500677ff40f1e3      0x1f5a8b59993bffa0
0x5585d30d8920: 0x1414c95000ab5165      0x21cafcd68910f494
0x5585d30d8930: 0x7dbef994994ec65e      0xa74533c21f26dfad
0x5585d30d8940: 0xd725bd8f285ee40d      0xfb2de0c3459dc685
0x5585d30d8950: 0xc065709d7945e182      0xfc6df3c79eeda7fc
0x5585d30d8960: 0x65c49c3f76d192a1      0xde0082a4cf4d469a
0x5585d30d8970: 0xd1b095052891b014      0xcd56a6ea336a09df
0x5585d30d8980: 0x86d15839f1986686      0x3883a724e2bf5d0f
0x5585d30d8990: 0xbd3c1afd1c90dedd      0xa215e9de5aaeac8b
0x5585d30d89a0: 0xcbcf20d234544383      0xe8cb016907e5d6a7
0x5585d30d89b0: 0x3315b1ff92edb550      0x713c677493c78b5c
0x5585d30d89c0: 0xe5e934c03056f20c      0x3172afd585d11e34
0x5585d30d89d0: 0xcbd0bb03c20dc14e      0x45afc95bb08c71b7
0x5585d30d89e0: 0xf34bb47a7199d5d5      0xa293916ec49700a4
0x5585d30d89f0: 0x9429fb4e99bd13a7      0xb76f3aa00bf6e4b4
0x5585d30d8a00: 0x23396525e3b082d7      0x67edbbb1a40db447
0x5585d30d8a10: 0xaccd9242e976d8e3      0x3cdf0c04bed51a39
0x5585d30d8a20: 0x1d2610c0a6a0a2d4      0x9fda31758c9dc9b4
0x5585d30d8a30: 0xea340e37a7655d31      0x656a7c83c7ebd649
0x5585d30d8a40: 0x82b3b7dacddde2d0      0x96a1b4f8442ce3c4
0x5585d30d8a50: 0x1f906a20843829a5      0x67578cfd69585621
0x5585d30d8a60: 0x891c3b75273c4a98      0xa9323db697c23ad7
0x5585d30d8a70: 0x9fd9ec2ce6c6bfc6      0x52a9c479ca7a854b
0x5585d30d8a80: 0xc16eb39bf2989c48      0x25cd77824cae73dd
0x5585d30d8a90: 0x1a6bb0fec31549e4      0xca447bf1cd510b5a
0x5585d30d8aa0: 0xd8b1d0f94b96ab2c      0xfb314ab16660e57b
0x5585d30d8ab0: 0xbe85d66e3888ebda      0xcaf013ebc83a48b8
0x5585d30d8ac0: 0x0abb853d85895ceb      0xa1f15001c23bc975
0x5585d30d8ad0: 0xdfcaae7ae74bc3d6      0x7636fef5b286dc6d
0x5585d30d8ae0: 0x4eaa11d6f4d6139a      0x046a0fd8783f2af7
0x5585d30d8af0: 0x958754d321e886f4      0x6d1f6e40c2010f61
0x5585d30d8b00: 0xbce6b065e2c91fce      0x636f61a4a9351c70
0x5585d30d8b10: 0x6a579100b6ad30a1      0xd583314625d5da8c
0x5585d30d8b20: 0x70b6c85a6163bb15      0x95e60536c329ffb3
0x5585d30d8b30: 0x78e2bdcbe9de0726      0x6ad25a530f30bac7
0x5585d30d8b40: 0x476049e69bf0bc14      0x94fda9c755397058
0x5585d30d8b50: 0x9301bd67069ed57f      0x7d8793e5e673773e
0x5585d30d8b60: 0xc46b3c86ed447ea0      0x83124df36a9270e5
0x5585d30d8b70: 0x9c19ccda91191f55      0x851518b047e9416b
0x5585d30d8b80: 0x7a1f605e073c8393      0x370174f1787e37d5
0x5585d30d8b90: 0xc865254de84dece6      0x5bf068ac892b8e32
0x5585d30d8ba0: 0x21e17fca52d75f6d      0xd17c71e5186e8adb
0x5585d30d8bb0: 0x12cd7af1f5040d4f      0xc6be91eaa7f5632b
0x5585d30d8bc0: 0x9998e769d33dfe78      0xf0ae1b2a3acc914f
0x5585d30d8bd0: 0x1601232ff70adf46      0x86fb6a19e0e15dbc
0x5585d30d8be0: 0x32762e046dc2a310      0x331ae745a0fd007b
0x5585d30d8bf0: 0x6526a6dc7dec8195      0x1e78083eca0ae63a
0x5585d30d8c00: 0x4ccc98ed9a510709      0x98b558a5312a3c58
0x5585d30d8c10: 0x088daf7ae604dbcc      0xefaa6c07af12bded
0x5585d30d8c20: 0xfe252fa8bc9ecb1f      0x0186315562aa2e19
0x5585d30d8c30: 0x19c8e07a2884364d      0x62453c8c42c4d52d
0x5585d30d8c40: 0xe2fb955daa9a221a      0x73f2a737da8d6a99
0x5585d30d8c50: 0xeac2a6d804bff4e2      0x1c18c28de7222896
0x5585d30d8c60: 0x6630c592a86603fe      0xba3d1d8af0ece587
0x5585d30d8c70: 0x6bd17fbc0ae1f824      0xdc2fbde40a624b83
0x5585d30d8c80: 0xfd5f4695593414e5      0x606b64a765f85a22
0x5585d30d8c90: 0x2690ad2eca0b2624      0xce192a0bea9339ee
0x5585d30d8ca0: 0x0c23bf21024355e7      0x52ba43948a2a372f
0x5585d30d8cb0: 0xa7bedbe3aaaad653      0xdab21826fb7432e9
0x5585d30d8cc0: 0x2cc4668ba1925430      0x48cf4ab4e5fee99f
0x5585d30d8cd0: 0x2f08362a5c773f55      0x78d90c90747efc7c
0x5585d30d8ce0: 0x459b923b3280717d      0x01c2314e8f0d40dd
0x5585d30d8cf0: 0x0e10410f21222594      0x02888f8ae68e00de
0x5585d30d8d00: 0x1ed516f6f5810de0      0x068f033f9525f965
0x5585d30d8d10: 0x5728de185cf1d04b      0xf804706fe3f4103b
0x5585d30d8d20: 0xd424ec6ed1a109f7      0x4aca0d1f7f512160
0x5585d30d8d30: 0x61d5ef5d6b1f64c4      0x0085a13ace1fc2bb
0x5585d30d8d40: 0xa3a87dafc5412928      0x017497fcdae824a5
0x5585d30d8d50: 0xc3b85c45790b9bc2      0x3c218734816bf661
0x5585d30d8d60: 0xd332dbf949e72a65      0x4a5795cf28980015
0x5585d30d8d70: 0x3785479ba74b9ac0      0xfa160e5b7c1a7522
0x5585d30d8d80: 0xa1410a5c15dbd36a      0x2d3c1bcc9188a015
0x5585d30d8d90: 0x6539211965ae05f0      0xe9f2720912eea23a
0x5585d30d8da0: 0x85496f4e32780a7f      0xbe12ac1c6a9a90e2
0x5585d30d8db0: 0x249234e908fa97e2      0x9496e9fe82489ff5
0x5585d30d8dc0: 0x4aee66a0c4043c5c      0x68c0db55f65ef5b1
0x5585d30d8dd0: 0xb0ff60a962f706d4      0xb13ac1fa0da58ad6
0x5585d30d8de0: 0xce8c2c9061e2aeea      0xe89abfc54381cc31
0x5585d30d8df0: 0x5ac38665a55e15b0      0xbf801efff6e091a4
0x5585d30d8e00: 0x0ffbd6b15bde8a86      0xbe480bf163d87779
0x5585d30d8e10: 0x14d6d245897537db      0x106369c30e7dccff
0x5585d30d8e20: 0x157dc88c257ecae7      0xe11689ebff3f88a9
0x5585d30d8e30: 0x78d014df443cff59      0x4091601c53eac36e
0x5585d30d8e40: 0x3f6ee00e7405947f      0xd7ef30231bafcc80
0x5585d30d8e50: 0xbd4ea5e15f37fd81      0x79bfa02822b91ff0
0x5585d30d8e60: 0x1038c6c6a4e433a9      0x5e03d436e7abc903
0x5585d30d8e70: 0x0d1dcb2d5cd376f9      0x9734267c39ceea2e
0x5585d30d8e80: 0x37e4b575f8974a53      0x4c9b3a9ac674200a
0x5585d30d8e90: 0x163ab7df86e089f1      0x9c77e398342fefb4
0x5585d30d8ea0: 0x9b5b9307188859b3      0x33a65b67c94a2dc1
0x5585d30d8eb0: 0x931360fa7372c3ab      0xcc70e758fb3f7b87
0x5585d30d8ec0: 0x6772dca7aeac125f      0x11e5541a79d8b0bb
0x5585d30d8ed0: 0x77d8afea0c7e8458      0x84fd69af4811ed5c
0x5585d30d8ee0: 0x2a2fe8f82b5f6bd5      0x9454e8de85cbd71a
0x5585d30d8ef0: 0xa875a7b3da6b53dc      0xc41ca6504687cfcd
0x5585d30d8f00: 0x8e82d547e2b9eb65      0xa1f99fb86efcac85
0x5585d30d8f10: 0x2bae8499713ffe3e      0xa2a9585400415c22
0x5585d30d8f20: 0xbc81af7b4839603a      0x17967a52a06090a6
0x5585d30d8f30: 0xa45d88357a861436      0x8cb0c6ffa1fbf2a1
0x5585d30d8f40: 0x7ecbbe6037cc4b3b      0x9b98e636a1fdaa2a
0x5585d30d8f50: 0x99ca3c8d5797aae7      0xecbd639a10dce6ca
0x5585d30d8f60: 0x968d030dfa270799      0xc3e724e6ebbb3cb9
0x5585d30d8f70: 0x6ab5493cfefe375b      0xfa1812ef98f6ae90
0x5585d30d8f80: 0xfe81bca8c084bed7      0xeb4b2b75a6e55158
0x5585d30d8f90: 0xaff3e5970b50c61d      0x191e19cf92f317f3
0x5585d30d8fa0: 0xa60fc6b790031f15      0x79b2cabd7e0b5368
0x5585d30d8fb0: 0xf275888308077fa7      0x4e1a6ec5a21a3382
0x5585d30d8fc0: 0x6b679329c4e0a432      0x5a0385f0c58b18f2
0x5585d30d8fd0: 0xdd2ac1d04d58f9ce      0x526a4f358cb37d6d
0x5585d30d8fe0: 0xd479f69eb203a1ad      0xe574b3fa7a2e5d74
0x5585d30d8ff0: 0x6302c9c4400bd48d      0xa21cf1eca6409555
0x5585d30d9000: 0xbe5cb728457de30b      0x542f580ed3e4a3a4
0x5585d30d9010: 0x3d83d33378682271      0x974aa558e908908c
0x5585d30d9020: 0x0b632b86b51c1329      0x5cf9bd0d75557d1f
0x5585d30d9030: 0xff648287173081e1      0xb9365c72592d75be
0x5585d30d9040: 0x2b46f73e172cd007      0x5c8bd41a90a2fbb9
0x5585d30d9050: 0xb5790bd98c2e7026      0xd5b58f167de66b25
0x5585d30d9060: 0x42b1de885002dc6b      0x7d72b4bab4486ccc
0x5585d30d9070: 0x282b14501d09e721      0xff1361e3c5647a34
0x5585d30d9080: 0xf0d92710e1d52d28      0x9060efd32f6bdb29
0x5585d30d9090: 0x4c8f14d49af55ffb      0x0f57e6a07a2f334f
0x5585d30d90a0: 0xe1cab2db2be04035      0x56421b23f8031e28
0x5585d30d90b0: 0xac3933c6944d191c      0xea649fdd852964dd
0x5585d30d90c0: 0xbc93cd2cf702fc94      0x2902b8783d3fbe41
0x5585d30d90d0: 0x4dae72f6545ccdcb      0xd06b4c1940e59ff5
0x5585d30d90e0: 0x96192430efedddd8      0x5575b0c238a79e65
0x5585d30d90f0: 0x17caf4dc47d6871d      0x0d03ead96b948ea1
0x5585d30d9100: 0xca9e1c7e3d4cfcc6      0x995d471ee9707a5b
0x5585d30d9110: 0x348c71ad4e02a517      0x056174da5169804e
0x5585d30d9120: 0x4e80701a90ae7aed      0x7bde1518876c30b3
0x5585d30d9130: 0xcf0d2278d83a131b      0x0e8223e45fa2457c
0x5585d30d9140: 0x301bbe36f17cdffd      0xb0f6639efc606105
0x5585d30d9150: 0xcec022193e2f05d2      0x40d2f6d8cc4f17d3
0x5585d30d9160: 0x7beb17a944bde322      0xb317ab69a5f32d5d
0x5585d30d9170: 0xe098f80e478fb90d      0x8eb70b51c8ad8055
0x5585d30d9180: 0x1935bdefed4b8113      0x11ab349afb6af145
0x5585d30d9190: 0xb5ddfc6c5a9a40e2      0x095beba5318eb729
0x5585d30d91a0: 0xfbae7bfe53fdcaf7      0x12184e78c7fdf86d
0x5585d30d91b0: 0xf302f4c14434c50b      0x216068872abe4e2a
0x5585d30d91c0: 0x25052e42b77684ad      0x0f78ece68d71ed92
0x5585d30d91d0: 0xa35a56e4478b4562      0x88ae6ea73170916e
0x5585d30d91e0: 0xcc7fc6d171a3925e      0x1a10a5f76aee7330
0x5585d30d91f0: 0x63d52a619dc93661      0x616536cdda3e70a8
0x5585d30d9200: 0xc666ea73569a9296      0x4b3d585ae32f3bb2
0x5585d30d9210: 0x43c7a26a8b4d0ba4      0x772329115ecd7090
0x5585d30d9220: 0x72ef01f28e2baa51      0xe5153a778f4d2684
0x5585d30d9230: 0x7126d9a8f149a50c      0x68b5c3bbdcb93fb9
0x5585d30d9240: 0x18dec6641b91cca0      0x2e26777e5e7237c3
0x5585d30d9250: 0xf7d00e12d889d05a      0x1d89805feaeaf19a
0x5585d30d9260: 0x4576c2de4d759c8d      0x9c9967491ea3e927
0x5585d30d9270: 0x4cae8f2ed3544bb9      0x7e38f64b1dcb4f52
0x5585d30d9280: 0xfa113c8fa54b3bab      0x37f580fec20cf383
0x5585d30d9290: 0x828303a1f95c7081      0x1899e45ea93c2454
0x5585d30d92a0: 0xc59a64f49ec63e4d      0xc42c518eb96a6e27
0x5585d30d92b0: 0xcfe38aabeb1fa56f      0x6864c751b2cbeb8d
0x5585d30d92c0: 0xd30bf1361eeeb768      0x466453237f9c283e
0x5585d30d92d0: 0x6947bed1d35d350a      0x3adaff35e16be41d
0x5585d30d92e0: 0xa053c7ea7735e465      0x0104a9431eb3cacb
0x5585d30d92f0: 0x5044d0e1c9751007      0x250c0e33bbec15b5
0x5585d30d9300: 0x8dbcb982dd3e8581      0xd07a939232799b4b
0x5585d30d9310: 0x956a81786300a2b0      0xed5590ad6d70b3bc
0x5585d30d9320: 0x56574f23d65678b9      0x213fc816aa0f4098
0x5585d30d9330: 0xc892995120565f3b      0x2846350fd4c9dd6c
0x5585d30d9340: 0xff46de2d4a1d72c9      0xbb497e980130076b
0x5585d30d9350: 0xeea73c00f7ff4f8d      0x31f52c385af42310
0x5585d30d9360: 0x5e8afedf173c6cec      0xec15e7e8af5707f3
0x5585d30d9370: 0x309002f99b0e7bc5      0x0e56371c6192793f
0x5585d30d9380: 0x1825c53ffd732acb      0x5d1aa603a9cbbcd2
0x5585d30d9390: 0xa38c1d387d933031      0x407d8996eb8cc735
0x5585d30d93a0: 0x58281e16e897555b      0xf89bfdc846aa225d
0x5585d30d93b0: 0x8e13d1c0d130fd15      0x853e4267e657440a
0x5585d30d93c0: 0x13a913a3d696b763      0xe4e596833a9a8c3f
0x5585d30d93d0: 0x2f819310b06b3662      0xcda6ac6dfd3f26ac
0x5585d30d93e0: 0x38e546349c502402      0xf520fdc427a5e11e
0x5585d30d93f0: 0x9ba19c329fe912bc      0x87754974d0a0a524
0x5585d30d9400: 0xa365980392ebe482      0xf990f22d8b4edfdf
0x5585d30d9410: 0x18b179df1f3eb211      0x1e30771a69dd3426
0x5585d30d9420: 0x7d0eb362de20fc84      0x891e4637d20d5ac0
0x5585d30d9430: 0xab169a29fcea0d6e      0x493804379f92084c
0x5585d30d9440: 0x5411c28357a7e2f4      0x5c191d9986b06934
0x5585d30d9450: 0xc9bc7f53f249dff1      0xd11969dab029b42e
0x5585d30d9460: 0x5e56eaf2b2da3bb7      0x845b5aec55d1b76a
0x5585d30d9470: 0x4e5553db73f1afb5      0x2637ef02abc5c003
0x5585d30d9480: 0xe5174960cb7db311      0x9bb3ce2a421811e6
0x5585d30d9490: 0x697e44f7aa7ffb11      0xe61d8aef69186067
0x5585d30d94a0: 0x1890cca92c7c3ce9      0xee2ca1fe56cdc045
0x5585d30d94b0: 0xe6a9496ac8c11303      0x615c53055310b0cd
0x5585d30d94c0: 0xe2f3f77088f247bc      0x3d26b046463bb55c
0x5585d30d94d0: 0x45716c8097a33329      0x062f14235b6bb199
0x5585d30d94e0: 0x363befdfcc83af10      0x03806feff4dc240a
0x5585d30d94f0: 0x9504003e218a690f      0x4dcd483a5b2acee2
0x5585d30d9500: 0xed7cba4018418c9e      0x03b47e871aa6c7ae
0x5585d30d9510: 0x49b5f6023bcdb0f4      0x781adcf8de6cd76a
0x5585d30d9520: 0x92f6fc5fd91be3d3      0x731af624d02bcaf8
0x5585d30d9530: 0x734496129e9ecb87      0x5f47d10c70199b39
0x5585d30d9540: 0xf5dfc3d009ded4dd      0xb481e2b329135fe3
0x5585d30d9550: 0x3d3bc3cb27f7cbfd      0x26a003600526b632
0x5585d30d9560: 0xd200917a6f4315d4      0x3ca82f93e9947d61
0x5585d30d9570: 0xba46c0f5d4d8c368      0x2c2f8ef7d82c1e50
0x5585d30d9580: 0x197220aa1c8df910      0x776bf511cd38bbe8
0x5585d30d9590: 0x9b76a8e8c5b2b984      0xf01fc03ab848669d
0x5585d30d95a0: 0x5496fe005fa84cd6      0x70e235a8eec66a11
0x5585d30d95b0: 0xfc472238ead88695      0x4219101665ce9218
0x5585d30d95c0: 0xc3fcbdb996e373f1      0xcee102595cd0d66f
0x5585d30d95d0: 0x745acf4efbb42c10      0x389f3cd2bf4e24dc
0x5585d30d95e0: 0x315d3dcbc65f5d78      0xa98cb50185094ef3
0x5585d30d95f0: 0x6c9f012c7722bf23      0x3aa77888d30efac4
0x5585d30d9600: 0x0a2d04ef8f87fe6d      0xb2ea2d4953b01f77
0x5585d30d9610: 0xadd1d4cc6bb6de73      0xe71f59ce82751f6a
0x5585d30d9620: 0xf4bb1c4ba8c8a142      0xb3ece1e4c7147438
0x5585d30d9630: 0x9851e6dbb34b98bc      0xe319e361526ed218
0x5585d30d9640: 0x047ff1bf270e5286      0x3a8d2da4d813ff76
0x5585d30d9650: 0x55cce854cdcc13c1      0x70a0649830c4a287
0x5585d30d9660: 0x3f4d9195dec0dcfa      0x9a3ab00a80be8f2a
0x5585d30d9670: 0xfb94e629b7de5ec6      0x287c22d5e1c92530
0x5585d30d9680: 0x62206f7b536f50d7      0x7ef9f3f1ce717552
0x5585d30d9690: 0xebc3c953dc061d75      0x03852969adf5ba64
0x5585d30d96a0: 0xe7045f07144481b9      0x92168f186f6e65e2
0x5585d30d96b0: 0x3553a2c6f22ca596      0x76a839fc5b220686
0x5585d30d96c0: 0xd651f9e1dd1e5ac4      0x1ebfedfea30afa52
0x5585d30d96d0: 0xabea6c1b0ffa5719      0xb9358b58402932af
0x5585d30d96e0: 0x2dda014c97b0677f      0x6c04c8b28c0d839a
0x5585d30d96f0: 0xd81580a4dc09fb8c      0x6923035e9f7d61d2
0x5585d30d9700: 0xd7473f7e62112e84      0xd3fa38316a094d1a
0x5585d30d9710: 0x0c2bf97aec2ab89b      0x8a768a57e95d4fc1
0x5585d30d9720: 0x42d30ca8d2dec164      0xe8f5d46b9c95b726
0x5585d30d9730: 0xddecaa3a43e26a17      0x0e70b33e84913854
0x5585d30d9740: 0x1e465495044f1a45      0x2746d8b83282b89b
0x5585d30d9750: 0xe0ae24877470e0fd      0x153dfb54d0e755d4
0x5585d30d9760: 0x9da317b0c7452871      0x4a4bdef07dcd8c3c
0x5585d30d9770: 0x852375df5072c7f7      0x2119d27a4fb4c53f
0x5585d30d9780: 0x4486a2d62c146f50      0x82f7f796f555607b
0x5585d30d9790: 0x20b0db2616bc1990      0x48ee005b08d24914
0x5585d30d97a0: 0x44e3a16c3f3d8bef      0x86323dc6abe9ceb5
0x5585d30d97b0: 0xcbaaaf19f7f69fe0      0xd3aaae1a63d7b57f
0x5585d30d97c0: 0x125b6f5433a94d22      0x7a0e2bda5ce938bf
0x5585d30d97d0: 0xeb1a15755e8c748a      0x764faef64e329462
0x5585d30d97e0: 0xa020759141b87564      0x82278eb2f6cf62ad
0x5585d30d97f0: 0xa7b5b7f01c94488c      0x4249c309a5fef727
0x5585d30d9800: 0x2a35db349688b2d1      0x250f1c0a81ad47f4
0x5585d30d9810: 0xbc040fcf95372d8b      0x611e611f04b4fe78
0x5585d30d9820: 0xb810e819517bbcbb      0x742470d22c7d9bce
0x5585d30d9830: 0x8ba9a2660f080967      0x9299710bc2182764
0x5585d30d9840: 0xa55f19dff748b2d9      0xa7d0269cf131b5b0
0x5585d30d9850: 0xe16bce5c9b7f646f      0xe1eb349baea50843
0x5585d30d9860: 0x6d3b676f30c8071c      0x7673320ec6d4b0a0
0x5585d30d9870: 0x1b6efe2455bc28e0      0xedf8e2033be09ee9
0x5585d30d9880: 0x9266fb917b668e36      0xf6c244f9cc752ab8
0x5585d30d9890: 0x4579d8546bbb93e7      0xcc253e5e19c05b8a
0x5585d30d98a0: 0xcb6158471867109d      0xf07b4a56089d4b01
0x5585d30d98b0: 0x4d623c2ad0d7facf      0xc4795ea2ecf3a669
0x5585d30d98c0: 0xf3626d6f10ca8520      0x85bf809d8f730fa4
0x5585d30d98d0: 0xb231b711d2a19f40      0x4403e1d78a78cee8
0x5585d30d98e0: 0x73bfab424225c8e1      0xb96afc987ecf815e
0x5585d30d98f0: 0xf764b2debeee33b3      0x43f225c4e75e0412
0x5585d30d9900: 0x95a638a8e8fbedbb      0xdb59745003b819a6
0x5585d30d9910: 0xbf8497d2f888f9e8      0xe70069a64e559fe6
0x5585d30d9920: 0x3221166c14c21a22      0x2782d8c284a29d67
0x5585d30d9930: 0xfe7b7c6661b6a31a      0xd1097828de61ac75
0x5585d30d9940: 0x763df727ce75b8cb      0xca2188e9d4ab4354
0x5585d30d9950: 0x12e063a58fb61d38      0x1a91ba728ca04b1e
0x5585d30d9960: 0x968e47063f310228      0xe575a6de79434f48
0x5585d30d9970: 0x115563c832185d3b      0x46066f9b155108cd
0x5585d30d9980: 0x235f5e853d570e03      0x5c41169a7cd0925c
0x5585d30d9990: 0x1cd8f1bbe70e074d      0x9c3a801500441cfb
0x5585d30d99a0: 0x0fa84fb0bf3afd1f      0x232869fc8d3984e3
0x5585d30d99b0: 0xbb314d84718ec6b4      0x4b637693c53b6f31
0x5585d30d99c0: 0xae4a4d59b0fc2ac9      0xb2d7ac332678b999
0x5585d30d99d0: 0x5f8fbd3c906894f2      0x3ab59fa7406192ec
0x5585d30d99e0: 0x4e5c363c6ecf3795      0x053655678acc3e6c
0x5585d30d99f0: 0xc6efcd657c5cf837      0x1e57b67f4040ad80
0x5585d30d9a00: 0x8d979d46c857f5ca      0x59ec3f7cdda84281
0x5585d30d9a10: 0x828c668d5a75daf6      0x4d6fe93e36d70ada
0x5585d30d9a20: 0x08ed879bffe6c195      0x8d85ca87be939c04
0x5585d30d9a30: 0x1ed483471b093d23      0x6e3a8ea99421a82e
0x5585d30d9a40: 0x7a55a74700ffcb9c      0x4969441a0a054bc4
0x5585d30d9a50: 0xf3b8cd452d4993b3      0x39e63588bb7030d6
0x5585d30d9a60: 0x8a40b7608004485f      0xc690500fd88227d2
0x5585d30d9a70: 0x213d4ee26bacaef6      0x6ceb15a58e8199ca
0x5585d30d9a80: 0xc2d731c1545617ff      0x9c36d248dbcf7413
0x5585d30d9a90: 0x0a3922fc8b1f19aa      0x049b3bdb840c13e3
0x5585d30d9aa0: 0xc1c77f326c95ad4c      0xef0df4de1a3334cc
0x5585d30d9ab0: 0xf01f1fcab2aef3ee      0xa3b8bfc2d2323b10
0x5585d30d9ac0: 0x2ba2b8e57a157339      0x0db8d4e3b53f547e
0x5585d30d9ad0: 0xe180c10eb0d5707a      0xb7a939e060f9233d
0x5585d30d9ae0: 0x8595f3bdcaf65da4      0x562bf4f2f28665c4
0x5585d30d9af0: 0x1723b29955104835      0xbbc6248afad14f41
0x5585d30d9b00: 0x58f43d98be1477ab      0x28e051c8b6c8c15f
0x5585d30d9b10: 0x01c7af69a5e8fd49      0xc3dff1152ea3155e
0x5585d30d9b20: 0xc628bc72a298c34b      0x030442fa026ad428
0x5585d30d9b30: 0x50299486ce1b24b0      0x42ae6bbb708efc7a
0x5585d30d9b40: 0x8efb0b5635cfd9e4      0xf07d506dc9cb085f
0x5585d30d9b50: 0x858939f3fab9635e      0x52d4152a6fead8ed
0x5585d30d9b60: 0xd6dda4727cc18dd5      0xd703b90205aad540
0x5585d30d9b70: 0xa8f531f4beeaacd5      0x52b6a9ea3ba96399
0x5585d30d9b80: 0x522695143740b9c3      0x81487f8518c39f82
0x5585d30d9b90: 0xa7f1bebbd11d2990      0xd6d8070b95b1a491
0x5585d30d9ba0: 0x30aaf5021d9da3c6      0xc2bd6123ce80568b
0x5585d30d9bb0: 0xd686d08de685b551      0xcb5568746c1bdd17
0x5585d30d9bc0: 0xf2493c7bfe359420      0xde466714e9af387e
0x5585d30d9bd0: 0xe189940b202a21d9      0x3db53d91141902b0
0x5585d30d9be0: 0xaa91809521b7d87c      0xca1a1d09dbc5260d
0x5585d30d9bf0: 0x3323faab8a69a422      0xb44641b410e19c6e
```

I tried using both the keys as-is in order to decrypt `data.enc` file by formatting the hex into base64 and then adding the appropriate header and trailer in a .pem file but it didn't work. So, we need to understand what the 'shielding' means. For this, I found these resources:
- https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/

So, shielding means that the private key is stored encrypted even in memory. However, the key used to encrypt it is also stored in memory so that we can get the key and decrypt it ourselves. This key is the 'prekey'.

I tried using the `sshkey_unshield_private()` function and the `sshkey_save_private()` in my own way to try and decrypt it; I also tried using the script and some other stuff but none of that worked. I tried placing the blobs into the memory of a debug session of `ssh-agent` (script is in [python file](../gdb_script.py)) and then calling the functions `sshkey_unshield_private` and `sshkey_save_private_blob`. Some resources about using python scripts for gdb:
- https://stackoverflow.com/questions/4060565/how-to-script-gdb-with-python-example-add-breakpoints-run-what-breakpoint-d
- https://sourceware.org/gdb/current/onlinedocs/gdb/Basic-Python.html#Basic-Python 

### Decrypting the shielded private key

I have to then understand how the prekey is used, which encryption was used, and how the shielded private key is decrypted in the source code.
> I also asked in 'Get Help' and got the advice that I should try reimplementing the algo myself and that it should be simple.

In order to understand how the shielded private key is decrypted using the prekey, let's look at the source code for the `sshkey_unshield_private(struct sshkey *k)` function in [sshkey.c](https://github.com/openssh/openssh-portable/blob/25c8a2bbcc10c493d27faea57c42a6bf13fa51f2/sshkey.c).

Some important variables/definitions:
- `u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];`
- `#define SSH_DIGEST_SHA512	4`
- `#define SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512`
- `ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH) == 64 bytes`
- `#define SSH_DIGEST_MAX_LENGTH	64`
- `#define SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */`

Inside the `sshkey_unshield_private(struct sshkey *k)` function, it does some sanity checks and then it calculates the ephemeral key. As part of this, it first calls this function to get the digest:
```
	/* Calculate the ephemeral key from the prekey */
	if ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
```
The result is stored into the `keyiv` variable. The function header with the parameters looks like this (defined in [`digest-openssl.c`](https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/digest-openssl.c)): 
```
int 
ssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen)`
```
and within it, it initialises the digest:
```
const struct ssh_digest *digest = ssh_digest_by_alg(alg);
```
The argument that was given for the algorithm was `SSHKEY_SHIELD_PREKEY_HASH` which was defined as `SSH_DIGEST_SHA512`. In this same file, it also has a struct for the different algorithms:
```
/* NB. Indexed directly by algorithm number */
const struct ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			NULL,		0,	NULL },
};
```
So, the algorithm which gets used is SHA-512.

Now, the function `ssh_digest_memory` stores the resulting digest into the `d` param, (the argument was `keyiv`). It calls `EVP_Digest` for it.
```
if (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), NULL))
		return SSH_ERR_LIBCRYPTO_ERROR;
```

Back in the `sshkey_unshield_private` function, after calculating the digest, it initialises the cipher:
```
	if ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
``` 
The function is declared like this in [`cipher.c`](https://github.com/openssh/openssh-portable/blob/800c2483e68db38bd1566ff69677124be974aceb/cipher.c):
```
int
cipher_init(struct sshcipher_ctx **ccp, const struct sshcipher *cipher,
    const u_char *key, u_int keylen, const u_char *iv, u_int ivlen,
    int do_encrypt)
```
So, here we see that the parameters are separate for the `key` and the `iv`. However, the arguments given are both using `keyiv`. The param and argument correspond like this:
- param `key`: argument `keyiv`
- param `keylen`: argument `cipher_keylen(cipher)`
- param `iv`: argument `keyiv + cipher_keylen(cipher)`
- param `ivlen`: argument `cipher_ivlen(cipher)`

The `cipher_keylen(cipher)` and `cipher_ivlen(cipher)` values I found by breaking at the function and then looking at the arguments. The `keylen` is 32 and the `ivlen` is 16. SHA-512 has a digest size of 64 bytes. So, the first 32 bytes of the SHA-512 digest of the prekey are the key and the next 16 bytes are the IV, the remaining 16 bytes are not used. 
```
pwndbg> i args
	ccp = 0x7fffffffd120
	cipher = 0x5555555d5170 <ciphers+240>
	key = 0x7fffffffd1e0 "\326\"{BCs\357\n\211\332\002\257̽\266}\253\004\346\310\344\250\376\232\307\v9\314U\326\030`A}!\360j\266g\274\064\251\217/Ъ\243\353(f>\214m\037\364\307\003p\315}IƎ\233"
	keylen = 32
	iv = 0x7fffffffd200 "A}!\360j\266g\274\064\251\217/Ъ\243\353(f>\214m\037\364\307\003p\315}IƎ\233"
	ivlen = 16
	do_encrypt = 0
```

We now have the key and iv for the cipher, but we need the encryption scheme. Earlier in the `sshkey_unshield_private` function, around where it does the sanity checks, it also executes the segment below. The `cipher_by_name` function is defined in [`cipher.c`](https://github.com/openssh/openssh-portable/blob/800c2483e68db38bd1566ff69677124be974aceb/cipher.c) and it returns the `sshcipher *` for the cipher specified as a string. Here, the argument given is `SSHKEY_SHIELD_CIPHER` which is a macro defined for `aes256-ctr`. So, the scheme is AES-256 using CTR mode.
```
	if ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
```
```
#define SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
```

Now, we can have everything we need to try and decrypt the shielded private key. Let's try to decrypt it using AES-256 in CTR mode with the key and IV derived from the first 32 and 16 bytes of the SHA-512 digest of the shield prekey.

I wrote a script for this which is in [x.py](./../x.py). The snippet which does this is this:
```
ctr = Counter.new(ivlen *8, initial_value=int(iv.hex(),16))
cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)

out_bytes = cipher.decrypt(shielded_private_bytes)
```

I outputted the  decrypted private key as bytes, base64 and as a string.

I then tried to output this decrypted private key into base64 format and add the header and trailer to form a .pem file and then use it to decrypt the `data.enc` file but it didn't work. There is still more to do...

> When using this didn't work, I was a bt confused about why.

### Parsing the decrypted private key blob

After a while, I realised that the decrypted private key bytes had the characters `'ssh-rsa'` near the beginning of it. That gave me an indication that these bytes are some kind of a struct which needs to be formatted properly. What we have is a decrypted blob of the private key, not the properly formatted private key. The bytes output looks like this:
```
>>> out_bytes
b'\x00\x00\x00\x07ssh-rsa\x00\x00\x01\x81\x00\xd4~\xff\x9aW\xecN\x00\xe8"~\xc3\x8d\x0b>N\x97\x8a\xb7\x82\xb1\x11z\xd3\xf4f\xc6\x82\x10\xc8\xd9hd\xe0]{\x805\xd2\xb7oj\xff\xba\x15T\x83\xd3\xf5\xfcm\xf7\xc5}\x16\xc5=>\xbf\xde(qD\xd7\x8a\x98=`y\n\xad\xe5\xa3\xa3?\xd8\xd6\xd1\xfc\x88j\xb9\xd9\xaa\xcf&\xa4\x93\xb6\x84\xd8\xf2\xa7\x9e\x9e\x04\x02\xea\x96\t~\x8ey\xde2?\xbb\x8d{4\xb4iF\xabJ\xe5!\x98\x94bP\xb4\xa0\x928\x8e\xa3@\xba-\x81$\xd0Q\x12\rW\xa8\r\xa1\x9a\x9d>S\xcd\xf1\x14\xd6\xc5\xb51\x1b\xdc\xab\xb0\xa7\xb6\x10\x84\x7f\xdb\xf6\xe9\xa7\xe1\xd8\xd2\xf9=`\xad$\xa3\xb3\xd2\x1b<\x05\xb5\xad\x8a\x8e\x96\xc7\xcf\xab\x97\xbdA\x8e\x89\x88\x00\x9cd\xf4\x18I\xd5\x18\xdbi\xa9\xac"\xfe\x96\xd9\xe5\xe8uI\xce\xbf}\x86\xf0F\xa5*\x87\x8d\x87\x91|\xc5\xbe.\x8e\xe3(\t?\x80\xeae\xf6eX\xa7[y\x1a\\\xd3\xcc\xb8\xf3\x94LM\xcb\xb9\xb8M\xd1\xe6\x9c\xe7\x0eYs\xc8\nK\xbeWYaR\xfcP\xc3\xe6L\xa0m\xd8/\xd1\xf0\xdd6!\x92\xf3\x8d\x0b\xc6c\xa8\xc952\x98,\xfc2\x8b2^\xb6\xd3\x07X\xb2\xf2\xde\xd9$n\xd9~\x82\x98\x14\x04\x86\xb5\xe3\x07\x8c\xdc\xc0\xd7\x97\xf6\xc7\x9a\x83WI\xef\xf7\xca\xc1\xff\xdb!u\xcc U\xe5\xe3\xa0\x9f\xdb\x1b\xc7\xcd6\xa5pk\x8e\x07^\x10 \xcb,\x03\xe5vt</\x1c\x0et\xa1\xd8\x9d!X<\xd3\xd3\xc3\xcb{\xf9\xe9\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x81\x00\x81\xb2\xd6N\x1dv5\x12&\x9d\xcfc\x8a6\x1f\x9c\x96\xb0k[\xd0\xb9\xcb\x8f\x8d0!\xdf\x87a \x19\xb0\xe0\xa5\x0eYn\x00\xa4G\xd46,\x1d\x12\xcd\xb7\xd4\xffs\x1bu%\xe9}\x0f\xe9\xb9\xf0^\x1c\xec\x98\xe6\x96\x0fxO\xc8\xed\xe5) \xde:z\xbc\x06x94 \xa09\xf9\xeb\x1f\xe1\x9ajT\x89l\xae#\xe2\xa7\xceV\x131\xe1>v\xcb!\xad\xb4R\xb1\xffC\xcc\x0fU\x95P\xec\xd8\xa9K\xe6i\xf9-N\x85\x96]i\xe2\xcfg|.:\x9foZ\x80\xe5\x93\x02Q\xc3\xe1%I\xddS\x11\x1fz\x87\xc3\x85\xc3\xc5+\xc9U\x86\xbe\x1a\x82^\x1b\x14\x94jy\xdf\x95E\x1b\xacb\x0b\xc6\xd5\xb8<]\xce\xea|\x1e^\xe2"\x1c\x8c\x8b\xbc*:mM]\x15q\x91q|~\xf8\xfa\x9cpJ\xa0\xb5\xc9\x94m\x17V\x15c\xc0\x1d\xf0XS8\x12\xc1\xd5\xb738\xd9\xad\xc9\x92\xee\xe8\xc6}\x909(\xca\x88S\xbd"\xa4\x05\x95\xade\xed\xaf\xc5\xea\x83\x03v$\x19\xdd|\xf9;\xaa$\xc2\xe4\xf3C)\xf6\x18\xac3+\xe6\x07\x8e%T\x01 \xed\xce\xf7\xda\xab[#\xd1.\x01\xe1[tv\x92\xe5\x9c\xef\x80\t\x94\x85xp@F7\x1d\xf3\xad\x93\xb1\x94=\x89\xeb\xcavY\x12\x85\x1b\xb6\x89Q\xff.\xcf\xda\x8a*\x04b\xa1Y\x04\xfbM\xde\x99\xc22s\x9a\xc9\t\xb1\x02\x1a\xd1\x1d8F\xfdV\xee\xa1\x9a(\x90\xcb}\x175\xc0\x9b\xdei\xdd\x9a\'(\x8b\xba8\xed\xa9\x95\x81\x00\x00\x00\xc1\x00\x91\\\x91\x95`\x01{\xff\x85\x88\xfbz,eF\xe5\x15%$Jl\x18\xe0\x0e=2\xae\xd4\x15k\xc3Rsn\xbe\xf7\xc1k\x8b@}\xebM\x83\xee@\\\x05~\x87+\xddXx\xad\x14ae\x8d\xe3\x02\n\xd9\xaf)7\xd3\xcc\xa4\x148\xc5K\x10\xbf\\\xc0x\xdf\x8f\xdc\xf7\x9a\xb8\xe9\x10,M`k\xe7A\x1a\x8d\xae\xf0\x14\xaa=X\xe4\xa3{04\xbd\xa5W\\\x0b\xac\xca\xb2o\x19b\xb54\x90\'v5\xc2\xd9\xc6|\x89h\xad\x97A\xceoL\xed\x03c$\xf4Px\xbcA\xe8\x1e*[\xa2\'.W\xf7.\xf7,1>\xb2\x9c\x86\xe0\x0e\x98D\xc8\x1c\xd0\x0c\x0e]IRc\xfbT\x9d<\xcdVu\x81\xf5\xcf\x99\x0b\x81\xb5\x94st\x0e\x10\x00\x00\x00\xc1\x00\xf7\xe0z)}\x90-\xf2jbx\xf7\xb4\n\xec\x1e\xd0/\xc6\xe4\xb9\xd9\xa7\xfc"\x9e<\x87\xbf\xeeW\x1b\xcd\xc2N\xec\xcdrHbT\xb8z\xd2\xc2O=\xc5w\xf7\x17\xef\x1a\xaf\xb1\x14C\xe0\xf6\\\xc6\x13\x94:\x88\xebq\xdbW\x1fVJU\x82\x95cp\x86\xf0Ll\xd3\xf6\x855\tkG\xf3;\xe5\x96\x9fq\xd5*\xa5L4B\xaa\xb1->\x93\x11\xc3\xd1\xe0\xd0%\xbae\xfb\xa1f\xfe0\xf8Ke\xf7q\x02\x8dyI\x04kA`Z\xac\x90\'\x0c\xa1-@\xda\x12\x8d\x08\xd18\x11\x07ID\xae\x1a\xa9\xeaV\x18s\xbf\t<4\x9d\x94\xf9\n|9\xf8>C+]h"\xe3ir\x1e\x0fa9\x9b\xa1\xc8\xd8\x96\x02\x032\x93\x97\xd6Y\x00\x00\x00\xc1\x00\xdbu\xb30\x99\xeb\xfd/\xe8z\x17\xfd\x00g\x8a\x14\xdb\xf0\x18\xd6D<M\x0f\xb2\x92\x96G\xd4\x12N\x81X\xd1\\\xc6SF\x1a\x99\xc2z\xa4\xe8\x1bgn~~\x9f_2>\x02\xc0\x032p\xe6\x05\x9e\x89\xb0\x03d\xba!85d\xe6\xa4\xda\x99\xea\x85)\x92g\x0fr\xe5~\xb9f\xbe\xbfe\xa5\x1a\x15\xc5&\xda`<Z\xda\xf0\x83\xd3QP\xed)\x19Js""\x85i\x19\xb9\xd6\xe6\x11\x96\x9a\xd6\xf3YX}\xe7\'\x07\xc0E\xee\xd7IDj\xe2\xc8\xf3u3PtJ~\xf1\x86\x93\xcd"\x89m\x97\xaa\xf3\x0b\xd2j\xe4\xbb\x01L\x9aY\xc5\xb9m{\x98(J)\xf3*;09\x88\xcf\x12\xec\x94F\xf7(\xfb:cH\xd9\x1a \xee\x11\x01\x02\x03\x04\x05'
```

In order to see what its contents are, we need to understand how to parse it.

For this, we should look at the function `ssh_rsa_deserialize_private` defined in [`ssh-rsa.c`](https://github.com/openssh/openssh-portable/blob/25c8a2bbcc10c493d27faea57c42a6bf13fa51f2/ssh-rsa.c). I found this by searching the repo for 'deserialize` and looking at defined functions.

<!-- **ssh_rsa_deserialize_private** -->

If we look at that function's code, we can see that it repeatedly uses the function `sshbuf_get_bignum2`. It also uses the functions `RSA_set0_key` and `RSA_set0_factors`. So, let's try to understand what they do. `sshbuf_get_bignum2` is defined in [`sshbuf-getput-crypto.c`](https://github.com/openssh/openssh-portable/blob/9d8c80f8a304babe61ca28f2e3fb5eb6dc9c39bf/sshbuf-getput-crypto.c). It then redirects by calling:
```
	if ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
```
That function is defined in [`sshbuf-getput-basic.c`](https://github.com/openssh/openssh-portable/blob/9d8c80f8a304babe61ca28f2e3fb5eb6dc9c39bf/sshbuf-getput-basic.c). It then calls `sshbuf_peek_string_direct(buf, &d, &olen)`, which is defined in the same file.
```
int
sshbuf_peek_string_direct(const struct sshbuf *buf, const u_char **valp,
    size_t *lenp)
{
```
Inside this, it gets the length by doing this:
```
	len = PEEK_U32(p);
```
This is a macro in [`sshbuf.h`](https://github.com/openssh/openssh-portable/blob/73dcca12115aa12ed0d123b914d473c384e52651/sshbuf.h):
```
#define PEEK_U32(p) \
	(((u_int32_t)(((const u_char *)(p))[0]) << 24) | \
	 ((u_int32_t)(((const u_char *)(p))[1]) << 16) | \
	 ((u_int32_t)(((const u_char *)(p))[2]) << 8) | \
	  (u_int32_t)(((const u_char *)(p))[3]))
```
What this does is it takes 32-bits (or 4 bytes) and interprets them as a little-endian integer. The first byte is shifted left by 24 bits, the next by 16 bits, the next by 8 bits and the last isn't shifted. This is implemented in python in [x.py](../x.py) in the function `peek()`
```
def peek(x):
    return x[0]<<24 | x[1]<<16 | x[2]<<8 | x[3]
```
The function `sshbuf_peek_string_direct`, after it reads the first 4 bytes as an integer and saves it as the length, moves the pointer `valp` forward by 4 bytes.


Back in `sshbuf_get_bignum2`, it does some stuff with bignums using the functions `BN_new()` and `BN_bin2bn(d, len, v)` ([manpage](https://man.openbsd.org/BN_bn2bin.3)). What this seems to be doing then, judging from how the length is taken using the first 4 bytes and the pointer is moved forward by 4 bytes, is that it is extracting the bignum from it of the length mentioned in the first 4 bytes.

The arguments given in the `sshbuf_get_bignum2` calls`rsa_n`,  also support this:
```
		if ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
```
```
	if ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
```
It seems to be getting the bignums and then placing them into the `rsa_n`, `rsa_e`, `rsa_d`, `rsa_iqmp`, `rsa_p` and`rsa_q` variables. The order is important because it seems to move the data pointer after exracting each bigbum. After that, it calls the `RSA_set0_key` and `RSA_set0_factors` functions. I confirmed that it is extracting bignums (or at least something) of the length defined by the first 4 bytes by looking at the output bytes I had (`out_bytes`). 

The first few bytes look like this:
```
>>> out_bytes
b'\x00\x00\x00\x07ssh-rsa\x00\x00\
```
The first 4 bytes are `b'\x00\x00\x00\x07'` and the following 7 bytes are: `ssh-rsa`. The following sequence of bytes follows the same pattern of 4 bytes for the length followed by the data of that length. Another confirmation is that at positions 400-407, we see this:
```
>>> out_bytes[400:400+4+3]
b'\x00\x00\x00\x03\x01\x00\x01'
```
The bignum here is of length `0x03` and the bigum is `0x010001`meaning 65537 which is a common value for the exponent `e` in RSA. 

So, we can extract the bignums after the 'ssh-rsa' in the following order: `n`, `e`, `d`, `iqmp`, `p` then `q`. The script [x.py](../x.py) has the code for this.

### RSA key as .pem

Now that we have the RSA parameters, we can initialise an RSA key object using PyCryptoDome in Python and make a .pem file using that. PyCryptoDome allows us to construct an RSA object using the exponents, factors, etc. See this: [`RSA.construct`](https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html#Crypto.PublicKey.RSA.construct) It needs the following values in this order:  `n`, `e`, `d`, `p` then `q`. Once we have this object, we can use the method `exportKey` to get the .pem file contents as a string. We then just have to write this to a file.
```
pvtkey = RSA.construct((bignums[1], bignums[2], bignums[3], bignums[5], bignums[6]))

# Export string
pvtkey_pem = pvtkey.export_key()

with open('privatekeys/PRIVATE.pem', 'wb+') as f:
    f.write(pvtkey_pem)
```

!! We now have the .pem key file we need. !!

### Decrypt `data.enc` 

The challenge has given us the command to use for decrypting the `data.enc` file:
```
openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc
```
We just need to tweak the filepaths and filename in this.

Once we decrypt it, we get the following output:
```
# Netscape HTTP Cookie File
suvwwcedmdcyelgn.ransommethis.net	FALSE	/	TRUE	2145916800	tok	eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM1Mzg3NTQsImV4cCI6MTY1NjEzMDc1NCwic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.O-6pNVAqeQ7id-eZN6yH0dRay6_4QAFtMlZg2ms2-Bg 

```


### Get the points

The token value here is `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM1Mzg3NTQsImV4cCI6MTY1NjEzMDc1NCwic2VjIjoiWFE4c255RXc4YXlpT1h0a0ZhcHNuQ2lrakR0bGw2MFYiLCJ1aWQiOjEwMjk0fQ.O-6pNVAqeQ7id-eZN6yH0dRay6_4QAFtMlZg2ms2-Bg`. We submit this and get the points.


### Summary

On a high level (very high level), the steps to get to the solutions can be summarised like this:
1. Find `idtab`
2. Find the shielded private key and the shield prekey
3. Decrypt the shielded private key
4. Parse its structure to get the exponents and factors
5. Make an RSA object in Python and export to .pem
6. Decrypt data.enc

## Answer
> Great job!