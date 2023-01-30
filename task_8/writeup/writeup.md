# Task 8 - Raiding the Vault - (Reverse Engineering, [redacted]) Points: 2000

**Description:**

You're an administrator! Congratulations!

It still doesn't look like we're able to find the key to recover the victim's files, though. Time to look at how the site stores the keys used to encrypt victim's files. You'll find that their database uses a "key-encrypting-key" to protect the keys that encrypt the victim files. Investigate the site and recover the key-encrypting key.

**Downloads:**

**Prompt:**

Enter the base64-encoded value of the key-encrypting-key

## Solution

The admin page shows us that we can request the key generation log. The [`keygeneration.log`](../keygeneration.log) file contains this information:
- Date and time of key generation
- Username
- Some kind of id (client id `cid`, as we'll find out later)
- Ransom amount

Our case is related to TiresomeSnake with user id `10294`, ransom amount `2.568`, and cid `62818`. We get the cid from task B1 which sent the `demand?cid=62818` request to this website.

If we look at the `/fetchlog` path in `server.py`, we can see that it takes the argument from the GET request param and then sends back the file. 
```
def fetchlog():
    log = request.args.get('log')
    return send_file("/opt/ransommethis/log/" + log)
```
So, we can exploit this and download the below files. All of these are references in the source code which is how we know they exist and their path.
- `keygeneration.log`
- `user.db`
- `victim.db`
- `keyMaster` binary

We can have a look at the data in the 2 DBs. It has information about all the logins to the website and the victims DB has partial information about the victims, or 'customers'. It doesn't have all the info because the keygeneration log has info which the DB doesn't.

The `keyMaster` binary is what is used to generate keys, get the unlocck keys, etc. as can be seen from the source code in `server.py`. The way that arguments are passed for each function can also be seen from how argv is passed in `subprocess.run`. So, in order to understand how the keys are generated, encrypted, stored or retrieved, we need te reverse engineer this binary. We should also be able to get the key-encrypting-key from it.

First thing to do: open in Ghidra. Looking at it in Ghidra, it's difficult to understand. Search Google for how to reverse engineer Golang binaries (in Ghidra or otherwise). Found this excellent resource: https://cujo.com/reverse-engineering-go-binaries-with-ghidra/.  I also found [another resource](https://isc.sans.edu/diary/Annotating+Golang+binaries+with+Cutter+and+Jupyter/24790) which wasn't as useful.

The cujo.com link explain a lot about Golang binaries and how they can be reversed. It also includes/references a Ghidra script which recovers symbol names---things like function names. It explains that Golang binaries contain the function names within them as strings. It also explains how strings work differently in Golang. Strings are not terminated by null characters, instead a string is defined by a starting address and a string length. So, the binary knows the string has ended by looking at the length instead if waiting to encounter a null character. This makes it hard for Ghidra, gdb and `strings` to find strings because they look for C strings (null char termination). Golang strings are also placed together in clumps---strings are concatenated together and placed together. For example, using `strings` on the binary gives one of these as a single string. We can clearly see that there are multiple things inside this such as an SQL keywords and queries, error messages, format strings, etc.
```
Invalid _journal: %v, expecting value of 'DELETE TRUNCATE PERSIST MEMORY WAL OFF'Invalid _query_only: %v, expecting boolean value of '0 1 false true no yes off on'json: invalid use of ,string struct tag, trying to unmarshal unquoted value into %vInvalid _foreign_keys: %v, expecting boolean value of '0 1 false true no yes off on'reflect.Value.Interface: cannot return value obtained from unexported field or methodreflect: New of type that may not be allocated in heap (possibly undefined cgo C type)x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)Invalid _writable_schema: %v, expecting boolean value of '0 1 false true no yes off on'Invalid _defer_foreign_keys: %v, expecting boolean value of '0 1 false true no yes off on'Invalid _recursive_triggers: %v, expecting boolean value of '0 1 false true no yes off on'Invalid _secure_delete: %v, expecting boolean value of '0 1 false true no yes off on fast'Invalid _case_sensitive_like: %v, expecting boolean value of '0 1 false true no yes off on'3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fInvalid _ignore_check_constraints: %v, expecting boolean value of '0 1 false true no yes off on'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefasn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %qINSERT INTO customers (customerId, encryptedKey, expectedPayment, hackerName, creationDate) VALUES (?, ?, ?, ?, ?)3940200619639447921227904010014361380507973927046544666794829340424572177149687032904726608825893800186160697311231939402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd166500051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f0000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd666864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151686479766013060971498190079908139321726943530014330540939446345918554318339765539424505774633321719753296399637136332111386476861244038034037280889270700544900010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899
```

When we run the Ghidra script, it recovers the function names. Now it becomes more tractable to reverse in Ghidra. One of the good things about this binary is that it has Partial RELRO (run `checksec` in pwndbg). This means that the addresses we see in Ghidra are the same as in gdb.

`main.main` is the main function here: main function in the main package. In this function, it checks the argv length and the command that was given. We can see this near the beginning of the functions where it compares some variable with `0x6f6c6e75` and then if `0x6b63` is next. If we look at the ascii values for these, it is `unlo` and `ck`, spelling out `unlock`. Here is the check, I renamed the variables to something more recognsable:
```
if (((lVar1_argv1_len == 6) && (*local_130_argv1_prefix == 0x6f6c6e75)) &&
    (*(short *)(local_130_argv1_prefix + 1) == 0x6b63)) {
```
The `lVar1_argv1_len == 6` is checking the length of the command given in argv, here 'unlock'.

Looking for similar checks in the function, we can find the checks for `lock` and `credit`.

For `lock`:
```
else {
    if ((lVar1_argv1_len == 4) && (*local_130_argv1_prefix == 0x6b636f6c)) {
```

For `credit`:
```
if (*local_130_argv1_prefix != 0x64657263) {
    return;
}
if (*(short *)(local_130_argv1_prefix + 1) != 0x7469) {
    return;
}
```

Now we know where each command will take us in the code.

I also looked at the strings and tried to find something interesting. I ran the command `strings keyMaster | grep db` and found strings relating to:
- DB queries
  - parameterised queries
  - table names
  - SELECT, INSERT, ATTACH, etc. queries
- X509 stuff
- '(>65535)'
- github.com/mattn/go-sqlite3._Cfunc_sqlite3_db_filename
  - github.com/mattn/go-sqlite3.(*SQLiteConn).dbConnOpen
  - github.com/mattn/go-sqlite3.(*SQLiteConn).dbConnOpen.func1
- Possible lead to DB name?
  - `cannot fstat db file %s`


> At this point I started reversing the `unlock` command using gdb and Ghidra. I ran gdb with just the command (no args) and got errors, and ran it with arguments taking hints from `server.py` code. Doing this gave me some insights but I stopped because it got difficult to understand and felt like I was going off-track.
>
> One more thing to do is that the binary uses a receipt.pub file and and some keys in the `unlock` flow. I tried to download this from the server but it was not accessible. So, I generated my own dummy files.

Reversing the `lock` command was more fruitful.

Let's try running the following commands and see what happens:
```
./keyMaster lock 62818 2.568 ImpartialStranger
```
This runs the binary with the `lock` command, the `cid` `62818`, `2.568` as the ransom and `ImpartialStranger` as the username. The order of the args can be seen in `server.py` and the values themselves can be taken from `keygeneration.log`.

A few things happen:
- We get an error in stdout:
  ```
  {"error":"no such table: hackers"}
  ```
- A file is generated called `keyMaster.db`.

The generated file tell us that there should be a database file on the server by that name in the same location as the `keyMaster` binary. So, let's try and download it in the same way as we did the other files.

In this DB, we can see some interesting things. It has a `hackers` table which only has the credits for ImpartialStranger, not very interesting. The other table is `customers` which has:
- `customerId`
- `encryptedKey`: this is the thing we want to be able to decrypt using the key-encrypting-key.
- `expectedPayment`
- `hackerName`: the user who generated the enryptedKey for the case.
- `creationDate`

Now that the DB exists with the `hackers` table, let's run the binary again to try the command. We will use TiresomeSnake because that's the hacker name in the `hackers` table with credits, we can modify the table and its entries (like adding more credits) in a DB explorer if we want as well. It gives this output:
```
$ ./keyMaster lock 43772 2.91 TiresomeSnake
{"plainKey":"dc467513-5e07-11ed-a332-9cb6d0b8","result":"ok"}
```
If we check the database, it also adds another row corresponding to this command (it also deducts the credits) but with an encrypted key. So, we can conclude from this that the program is generating a plainkey and printing it out, and alongside this it is also saving it to the DB but as an encrypted key. What we need to do now is to follow the program and see where it generates the plainkey and then when it encrypts it. If we can inspect the binary (in Ghidra and gdb) in between that, we should be able to find what (the key-encrypting-key) it is using in order to encrypt the generated plainkey.

Also to keep in mind is that the plainkey is in the format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx`. If we run the command repeatedly, we will also see that the plainkey doesn't change much. It also remains similar irrespective of the argumentss given as long as they are in the correct format.

Diving back into Ghidra, we can see that there is a function call in the `lock` command flow in the main package called `main.DchO32CDDK0`. Let's try to break at this call in gdb and see what it returns. We see that it returns a plainkey in `rax` with some additional chars (last 4 chars). Example at time of writing:
```
*RAX  0xc00001c3c0 ◂— '93e76cf4-9826-11ed-b49c-9cb6d0b86c1d'
```
So, now we know where it generates the plainkey. Next, we need to see where it prints, encrypts or inserts into DB.

> Be warned that Ghidra decompiled view doeesn't show everything. There are function calls and instructions that are only shown in the disassembled view and not the decompiled view.

If we continue stepping in gdb, it eventually calls the functions `time.Now` and `time.Time.Format`. It then calls another function in the main package, `main.mtHO6enMvyA`. Breaking at this function, we see these arguments in the registers (at time of writing, yes, you can see the time and timezone):
```
 RAX  0xc00001c3c0 ◂— '93e76cf4-9826-11ed-b49c-9cb6d0b86c1d'
 RBX  0x20
 RCX  0x30
*RDX  0x0
*RDI  0xc000016240 ◂— '2023-01-19T10:53:21-05:00'
*RSI  0xc00012bd20 ◂— '2023-01-19T10:53:21-05:00'
 R8   0x7ffff7d2f108 ◂— 0x0
 R9   0x1
*R10  0x7ffff7d38228 ◂— 0x0
*R11  0xc000016240 ◂— '2023-01-19T10:53:21-05:00'
 R12  0x0
 R13  0x0
 R14  0xc0000021a0 —▸ 0xc000128000 ◂— 0x0
 R15  0xffffffffffffffff
 RBP  0xc00012bf70 —▸ 0xc00012bfd0 ◂— 0x0
 RSP  0xc00012bd78 —▸ 0x7fffffffdf25 ◂— 0x7269540031392e32 /* '2.91' */
*RIP  0x5b9e27 ◂— call   0x5b8760
```

Let's look inside this function now in Ghidra. Looking at the disassembly, we see that `crypto/rand.Read` is called followed by `main.p4hsJ3KeOvw` and then `crypto/aes.NewCipher`. We can look up the documentation for the crypto functions here: https://pkg.go.dev/crypto/rand#Read and https://go.dev/src/crypto/aes/cipher.go The function `aes.NewCipher` is more interesting because it initialises a new AES cipher and it takes the key as its input. So, let's break at the function call in gdb and inspect what the registers have and see if we can get the argument. We break at `b *0x005b87d5`. The registers:
```
*RAX  0xc000016280 ◂— 0x625aa437d62957dd
 RBX  0x20
*RCX  0x20
*RDX  0x20
*RDI  0x0
*RSI  0x0
*R8   0x20
 R9   0x1
*R10  0xc0000162a0 ◂— 0x720c66d3c09461d0
*R11  0x20
*R12  0x1000
*R13  0x2
 R14  0xc0000021a0 —▸ 0xc000128000 ◂— 0x0
*R15  0xe29a5ced
*RBP  0xc00012bd68 —▸ 0xc00012bf70 —▸ 0xc00012bfd0 ◂— 0x0
*RSP  0xc00012bcd0 —▸ 0xc000018400 ◂— 0x4646aea1156dbd54
*RIP  0x5b87d5 ◂— call   0x4a5120
```
From this, I surmise that the key argument must be either in `rax` or `r10`, but probably `rax` because the function call is immediately after the previous main package function and so the argument is directly coming from the returned value of that function.

Let's see what the bytes are at the location. The key should be 0x20 bytes (32 bytes or 256 bits).
```
pwndbg> x/4gx $rax
0xc000016280:   0x625aa437d62957dd      0xa441235369666a4d
0xc000016290:   0x90cf0e85863e6aef      0x6aa583d289cf987f

pwndbg> x/s $rax
0xc000016280:   "\335W)\326\067\244ZbMjfiS#A\244\357j>\206\205\016ϐ\177\230ω҃\245j\320a\224\300\323f\fr\276\270y\331\177\355\254\215\227\247\246\221\211\355j\224\034Q\006_\264\260\357]"
```

Ok, so let's try converting these bytes into b64 as the answer requires. The script is in `x.py`. The b64 string is: `3Vcp1jekWmJNamZpUyNBpO9qPoaFDs+Qf5jPidKDpWo=`. Let's give this as the answer. It works!

This is sufficient to find the answer but we can also also explore the `main.p4hsJ3KeOvw` function to see what it does. Inside it we can see that it loads a string into `local_40` variable. It's a long string which begins with `RpDUR2kucEpjQ1A7ANZRdCWN4Kr00RSFbhpoii0Ft2o=`. Recall how strings in Golang aren't null terminated. Later on in the function, we also see that ` golang.org/x/crypto/pbkdf2.Key` is called. The documentation is here: https://pkg.go.dev/golang.org/x/crypto/pbkdf2 It tells us that it derives a key based on a password (a PBKDF, password based key derivation function). The arguments are like this:
```
uVar2 = golang.org/x/crypto/pbkdf2.Key(local_20,local_40,local_10,local_30,local_38,0x1000);
return uVar2;
```
Ghidra shows arguments in a messy way, but the idea is that the string is passed into the function. If we look in gdb, it will show us that the arguments include the string length as well. The key derived from this function is immediately returned. So, we can conclude that the key-encrypting-key we want is derived using this string which is a 'password' for it.

I renamed the function to ` main.p4hsJ3KeOvw_get_pbkdf_key`. It helps with keeping track. I also renamed the previous functions we saw, it makes things easier.

## Answer

The key-encrypting-key in b64 is `3Vcp1jekWmJNamZpUyNBpO9qPoaFDs+Qf5jPidKDpWo=`

> Great job! I think we've almost got their files back.
