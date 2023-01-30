# break main.main
b *0x005b99a0

# break "unlock"
b *0x005b9a08

# break os.ReadFile("./receipt.pub")
b *0x5b89d1

# break github.com/golang-jwt/jwt.ParseRSAPublicKeyFromPEM();
b *0x5b89e0

# break parseWithClaims
b *0x5b8a52

# break call keyfunc
b *0x599496


# break cmp "lock"
b *0x5b9c14

# break main.gen_plainkey
b *0x005b9d66

# break main.mtHO6enMvyA_some_rng_ops()
b *0x5b9e27

# sql - main.XL95gzwGuD8_some_sql
b *0x005b9f6e

# sql SEL query
b *0x005b8c75

# break sql prepare
b *0x5b8d11

# break b64 encode
b *0x005b8d87

# break sql exec
b *0x5b8eae

# break main.some_rng_ops()
b *0x005b9e27

# break crypto/rand.Read
b *0x005b87c2

# break main.get_pbkdf_key
b *0x005b87d0

# break crypto/aes.NewCipher
b *0x005b87d5

# break cipher.NewCBCEncrypter
b *0x005b8844

# --
# reversing gen_plainkey

# break os.Getenv
b *0x005b93d2

# break uuid.NewUUID -> uuid.GetTime()
b *0x0059d304

# break uuid.encodeHex
b *0x005b9444

# break runtime.slicebytetostring() 
# rbx has uuid string arg
b *0x005b9458

# set CLOCK_SEQ
set environment CLOCK_SEQUENCE=11