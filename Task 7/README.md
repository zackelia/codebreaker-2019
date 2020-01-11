# Task 7 - Distrust - (Reverse Engineering; Cryptography, Exploit Development)

*The arrested terrorist (see Task 3) was not cooperative during initial questioning. He claimed we’d never defeat the underlying cryptography implemented in TerrorTime and the only way to read encrypted messages was if you were one of the communicants. After additional questioning, he revealed that he is actually the lead software developer for TerrorTime and the organization leader directed him to provide a secret way of decrypting and reading everyone's messages. He did not divulge how this was possible, but claimed to have engineered another, more subtle weakness as an insurance policy in case of his capture. After receiving this information, the analysts who found TerrorTime on the suspect’s mobile device mentioned seeing an executable called keygen on his laptop. The terrorist confirmed it is an executable version of the library included with TerrorTime. They have shared a copy of the keygen executable for you to reverse engineer and look for potential vulnerabilities. As expected from the terrorist's statement, the chats stored on the server are all encrypted. Based on your analysis of keygen, develop an attack that can decrypt any TerrorTime message, including those sent in the past, and use this capability to decrypt messages from the organization leader to other cell leaders. Completing task 4 and task 5 are recommended before beginning this task. To prove task completion, submit the following information:*

1. *Plaintext version of the latest encrypted message from the organization leader*
2. *Enter the future action (i.e., beyond the current one) they are planning*
3. *The target (of the terrorist action’s) identity (First and Last Name)*
4. *The location where the action is to take place*
5. *Enter the action planned by the terrorists*

*Downloads:*

* *TerrorTime Key Generator (keygen)*

## Solution

For this task, we need to identify the vulnerability in key generation so that we can decrypt any message on TerrorTime.

Since the keygen is a standalone version of the keygen used in the APK, we will find where it is called in the application to see if there are any arguments. Looking in `generatePublicPrivateKeys`, we see this call:

```java
ref = Keygen.generateRsaKeyPair("alg1",0x800);
```

Within the app, new keys are generated using `alg1` and `0x800` (2048). Let's try to run `keygen` and see if we can get any more info. Luckily, there is a help dialog.

```
$ ./keygen --help
tsuite_keygen 1.0
TerrorTime Dev Team
Generates TerrorTime encryption keys

USAGE:
    keygen [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -s, --keysize <SIZE>       Size (in bits) of the key to generate [512, 1024, or 2048] [default: 2048]
    -e, --privout <PRIVOUT>    Output the generated private key to a file
    -o, --pubout <PUBOUT>      Output the generated public key to a file
```

From this, we are still not sure what `alg1` refers to but `0x800` is the keysize. If we run `keygen` with no arguments, it outputs a 2048 bit key pair. One interesting thing to notice is that the time it takes to complete has significant variability which indicates some random noise happening during the generation. Since all `keygen` does is produce key pairs, it is clear that there is some vulnerability related to those keys, particulary the public key since that is all we have access to for all users.

This is all the information we can find without reverse engineering, let's now put `keygen` into Ghidra to analyze it. If we look at the main function, we see that a lot of functions have lost their names:

```
hf352330e5765cc35(local_458,&local_918,0x1bd107,1);
hcc557fe57e61670a(&local_918,local_458,0x1bd02c,7);
h09d64e0158179fe9(local_458,&local_918,0x1bd08f,4);
h85f66caad92f2152(&local_918,local_458,1);
h4b287696c8056b09(local_458,&local_918,0x1bd093,4);
```

Luckily, at the top of each function, Ghidra has a comment with the function's namespace which includes its name. As we go through functions of interest, we will rename all of these.

Looking through the `keygen::main` function, we see that it is parsing arguments and matches what we saw in the help dialog. We also see references to `.rs` files indicating that this program was created using Rust. If we look at the call graph, we see that it is calling `terrortime::keygen::generate_rsa_key` which sounds like it would do the bulk of the processing. In here, we see that there are calls related to the algorithm argument we saw earlier: `gen_key-alg1` and `gen_key-alg2`.

Skimming through the `alg2` version, we see organized calls to the keygen common library and it closely follows [RSA key generation](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation) standards. This appears to be the "normal" algorithm. Looking at the `alg1` version, it is over twice the amount of code with even more functions called and many jump statements that interrupt the code flow. This version of the algorithm is presumably the one with the "subtle weakness". In order to understand this better, we will write some pseudocode and break apart the unfamiliar functions.

```
public_key_from_pem // What public key is this using?
get_r_keys // What are r keys?
generate_safe_prime // Why is this only called once?

while True
    for 1 to 10:
        bn_xor(prime, r_keys)
        if key_size - 1 < xor_bits:
            RSA_public_encrypt
            exit while loop
        r_keys += 1
    permute_r_key // What does this do an r key?

get_rand_bytes

for 1 to 1000:
    div
    if is_prime then break
    add 1

base64encode 2x

// The rest of the "normal" code
compute_modulus
compute_phi_n
compute_crt_params
set_factors
set_crt_params
public_key_to_pem
private_key_to_pem
```

Looking at the pseudocode, we immeadietly notice how this algorithm deviates from the standard key generation algorithm. Instead of generating two primes and computing modulus, etc., it generates one prime and it must create the other prime based off of it. If we can decode how this process happens, we can write a simple program to reverse this process to get one of the primes. Since we have the public key already we can get the private key if we know one of the primes. First off, let's look at the functions that are not clear.

The initial call to `public_key_from_pem` indicates that there is another public key embedded in the program because at this point, we have not even generated primes to use. If we use strings, we can find this key.

```
$ strings keygen
...
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAOCHl1mJGdeMZeRlrK1FPc4Hz2tWP+/B
rI2Stv5jXkABAgMBAAE=
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIDUp+79FlxC8TZYfvdx7RVzHURpwztQ
5YBiPfLm/Y+R+IhRb9U5newd4IcahRrvPgbvGojhZ3HniTpR0tiprr0CAwEAAQ==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpv2z8YCzCf5XR3tvWWfyXK+Yi
Z8nYzG8gxxNLSdYsOWiZVrgL8VJWCnd97t4NW1Nj9tXhAEwc4D1wECD7haHu4liI
uF1rt24okhg7LDVD4J6f02HOd2JA2oPVUazooq5J/gHZy3ZdR01BbJszZxM0zK95
LQSaJ+FV6hRrL0S2eQIDAQAB
-----END PUBLIC KEY-----
...
```

There are actually 3 keys in the program! We see that these keys are 256, 512, and 1024 bit respectively. Since `keygen` has three different sizes of keys to generate, we can assume that generating a key of size `n` uses an existing public key of size `n/2`.

Now that we know what public key is being used, we need to figure out what r keys are. We can see that when `get_r_keys` is called, it is passed the public key from before. This indicates that certain r keys are associated with certain public keys. In this function, `base64decode` is called twice and it returns these 2 decodings concatenated together. When we found the public keys in the output of `strings` there were also several base64 encoded strings immeadietly following:

```
pTo199138gu60LE4sX/pjMnQ5l3LIQ1acv7229NLz3M=
uR3vgJADCGRzjjD83RJACtktZed7gkeU7VUa6wGNwlU=
nZC6sIqXhjcIDtNgOmDMZMaCnYIj3obAvCU7u9uZEcOW9zhvZlSRSiR4BKkudAnIb4rtPCSs9rb8hTaTpZQWwQ==
ypSGX62TaKsVL3/9OMWdbvDlkc/Shm5IYbotRGOyx8xuoU8fjTv6grPAi5BEe+xiBRDFTlFPIMEZPpaZ+z/SBQ==
KR6tXlSIS17fgeJFIsHWRFiuChSy3Nunk1f2kV0QXH7StBRb2NtDqZUesPIttLzFkH+fsImW2JwX3DBaVfvHYTy6Chpv85sCEQLt15NEnJhLuPZb0ACcO8LMspcwODMklYoGEncZYiwMOy5ogApb0QAxkKVZvUJg7+TE0J/KlG0=
mqHamGlJxHeYfje5sJAKp3goHpJZFGOeWFKZrRL5LcjiN4oWkCcaSM3LZ/Sz+DZLk1Y/w5NJzd2bxRPRtIscmoymE8LEhslX9ADZX4wdZd/VTXkMqOvngKiyOTM7ajA5ZdK0uKywFppPguprzFie4/oziD54c9kKyXVvjIHqHe0=
```

If we decode these strings, the pairs are also 256, 512, and 1024 bit respectively. Each public key is associated with 2 r keys which we will call `r1` and `r2`.

The last function we need to check is `permute_r_key` to see what happens to the r keys in certain situations. The function is one large `switch` function with three cases which represent the three different key sizes. The permutation is actually just hashing and depending on the key size, the r key will be hashed with different algorithms. It will either use sha256, sha512, or sha512 (twice concatenated). This works because each of the resulting hashes are the same size as the corresponding r keys.

Now that we know what each step of the algorithm does, we can attempt to reverse the process. The first roadblock is that in order to decrypt something encrypted with the public key, we need the corresponding private key and we only have public keys. We are able to get around this though, since one of the keys is small in terms of cryptography. Since the smallest key is only 256 bits, we can use Python and a program like [Yafu](https://github.com/DarkenCode/yafu) to efficiently crack it and get the private key.

```python
$ python
>>> from Crypto.PublicKey import RSA
>>> with open("256.pub", "rb") as file:
...     key = RSA.importKey(file.read())
... 
>>> key.n
101557647013968786366704941067574978054561666345821498475177540145292429377537
>>> key.e
65537
```

```
$ ./yafu
>> factor(101557647013968786366704941067574978054561666345821498475177540145292429377537)
...
Total factoring time = 1.5107 seconds

***factors found***

P39 = 331913215069492253952942637983545292803
P39 = 305976509530377659301046399821722628779
```

Now that we have the two primes, we are able to recreate the private key.

```python
from Crypto.PublicKey import RSA

def mod_inverse(e, phi):
    a, b, u = 0, phi, 1
    while e > 0:
        q = b // e
        e, a, b, u = b % e, u, e, a-q*u
    return a % phi

n = 101557647013968786366704941067574978054561666345821498475177540145292429377537
e = 65537
p = 331913215069492253952942637983545292803
q = 305976509530377659301046399821722628779

phi = (p - 1) * (q - 1)
d = mod_inverse(e, phi)

params = (n, e, d, p, q)
key = RSA.construct(params)

with open("256.priv", "wb") as priv:
    priv.write(key.exportKey())
```

After running this script, we get the 256 bit private key:

```
-----BEGIN RSA PRIVATE KEY-----
MIGrAgEAAiEA4IeXWYkZ14xl5GWsrUU9zgfPa1Y/78GsjZK2/mNeQAECAwEAAQIg
IY3h3m2QwReoOoO/VH2eiJ4GdNEvV71TUCfruh/A96kCEQD5tCj0tmtrMr5BphWl
AfgDAhEA5jDupI1PGjmt++j36t8yqwIRANTSYYnYpIs0L4YieRYvLGMCEQCrLCvp
lWMDH20vbDgfIcZtAhAHl5yF+lWgFZgJK0nY0Mhx
-----END RSA PRIVATE KEY-----
```

Since we have the private key, we can reverse the key generation process for the 512 bit public key to get its private key. By iteratively doing this process, we will be able to get the private key for any pubic key generated with `alg1`.

Putting all of this information together, we can create [`exploit.py`](exploit.py) and use it to get the private key of any user. We will give the script the user's name and are given back their private key.

`$ python exploit.py hannah`

Now, we will put Hannah's public key in the database, encrypt her private key using AES from task 6 and put it in the database, and log in using Natalie's credentials. We are now able to read Hannah's past conversations! Once again, we need to analyze the conversations.

Last Message Sent:
```
Hannah: we're counting on you, Isabelle and Gittel. 
```

Target and action - Nathan Jones, kidnapping:
```
Gittel: The bartender team are prepared for the kidnapping of Nathan Jones
```

Location - gym:
```
Gittel: want to make sure I can tell the bartender team the right time Nathan is expected to be dropped off at the gym
```
**Note:** We have to login as Gittel to see her discuss this with her team

Future action - assassination:
```
Hannah: will that fund future projects?
Anjali: It will at least fund the assassination we've begun planning
```

That's all for the Codebreaker Challenge! We have succesfully cracked the encryption for TerrorTime as well as discovered and thwarted the terrorists' plans!
