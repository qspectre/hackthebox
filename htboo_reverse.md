# Write-ups for Reverse Challenges

## Meeting

Elf binary. Instant IDA analysis shows that `sup3r_s3cr3t_p455w0rd_f0r_u!` is the password that will spawn a shell.

![image](https://user-images.githubusercontent.com/115867891/198037771-2692d37a-66f8-439e-bfa3-113d83dc1ef3.png)

Small py script that will connect to the docker machine and send the payload:

```
from pwn import *


def pwn():
    io = remote("161.35.164.157", 32549)
    print(io.recvuntil(b"meeting?"))
    io.send(b"sup3r_s3cr3t_p455w0rd_f0r_u!")
    io.interactive()


if __name__ == "__main__":
    pwn()
```

We simply hit enter and enter the shell, and look for flag file. We find flag.txt -> HTB{1nf1ltr4t1ng_4_cul7_0f_str1ng5}

```
[x] Opening connection to 161.35.164.157 on port 32549
[x] Opening connection to 161.35.164.157 on port 32549: Trying 161.35.164.157
[+] Opening connection to 161.35.164.157 on port 32549: Done
b'\x1b[3mYou knock on the door and a panel slides back\x1b[0m\r\n|/\xf0\x9f\x91\x81\xef\xb8\x8f \xf0\x9f\x91\x81\xef\xb8\x8f \\|\x1b[3m A hooded figure looks out at you\x1b[0m\r\n"What is the password for this week\'s meeting?'
[*] Switching to interactive mode
" sup3r_s3cr3t_p455w0rd_f0r_u!

The panel slides closed and the lock clicks
|      | "Welcome inside..." 
/bin/sh: 0: can't access tty; job control turned off
$ ls
ls
flag.txt  meeting
$ cat flag.txt
cat flag.txt
HTB{1nf1ltr4t1ng_4_cul7_0f_str1ng5}
```

Flag is `HTB{1nf1ltr4t1ng_4_cul7_0f_str1ng5}`


## Ghost Wrangler

Running the elf executable will show this:

![image](https://user-images.githubusercontent.com/115867891/198062002-e31ea59d-4882-4de5-984a-5c56f6057b3c.png)

Meaning that there is a space in memory in that "box" where the flag is hidden. 
In IDA, we see a `get_flag` method. Although I could have looked over it there, I stepped through it with gdb/gef. Suddenly we reach this step:

![image](https://user-images.githubusercontent.com/115867891/198062440-65cfcb6a-49fc-4e89-845f-49fa26db3b98.png)

-- where eax was the first characater from this set of characters shown in IDA:

![image](https://user-images.githubusercontent.com/115867891/198062679-11f434dd-f5c7-4932-9f4b-4674db91a120.png)

If we look at eax register, we see: ![image](https://user-images.githubusercontent.com/115867891/198065482-4989f9e1-c163-40a9-8e9f-0f33bce2b54c.png)
--> which is hopefully 'H' (from HTB{...})

Therefore, if we see a xor eax, 0x13, it means we can use `CyberChef` to xor all our chars wit 0x13. So we get:
![image](https://user-images.githubusercontent.com/115867891/198062947-99c1f8d1-218f-4df6-8cb0-190f7622123d.png)

Flag is `HTB{h4unt3d_by_th3_gh0st5_0f_ctf5_p45t!}`


## Encoded Payload

This was done with Andrei Santoma, where we both brought something to the table.

If we dissasemble the code in IDA, we see the following instructions:

```
LOAD:08048054 D9 E8                             fld1
LOAD:08048056 D9 74 24 F4                       fnstenv byte ptr [esp-0Ch]
LOAD:0804805A 5B                                pop     ebx             ; ebx = EIP
```

This clearly indicates a shellcode (my discovery). We tried manually reversing the shellcode, but we got lost in translation. SO we thought to isolate the shellcode and run it in a Kali x86 machine (since this is an x86 ELF).

Gdb is not really your friend for this, because there are no symbols, so we cannot put breakpoints. Andrei had the idea to inject `0xCC` (int3) opcode to force the debugger to break.

Therefore, we managed to step through the code.

![image](https://user-images.githubusercontent.com/115867891/198264210-5e78b6e4-b79f-45e3-a4e7-88bfe8c57d95.png)

We figure out that there is a loop there (`jne 0x8048079`), so after stepping through it a few times we put a breakpoint after the loop. Going forward, we see interesting strings inside the debugger.

![image](https://user-images.githubusercontent.com/115867891/198265807-d88ee9f9-5716-48ab-bd8e-fcac0d2ee0f1.png)

A few instruction further, we also see the flag in the debugger.
![image](https://user-images.githubusercontent.com/115867891/198265907-31e5a126-1424-4cd5-8d84-6cbc2b52df30.png)

Flag is `HTB{PLz_strace_M333}`


## Ouija

This was not a fun one. If we let this run in Kali, it will print the flag after... 1 hour maybe. I also tried replacing the `bf 0a` instruction (which sets the timer for sleep) to `bf 00` but the program crashes...

So in IDA, we see a simple algorithm that parses each character of `ZLT{Svvafy_kdwwhk_lg_qgmj_ugvw_escwk_al_wskq_lg_ghlaearw_dslwj!}` which is definetly the flag.

We can see structures like this:

![image](https://user-images.githubusercontent.com/115867891/198266574-135a015b-c7f4-4b04-a33d-c885d1298bd5.png)

So of course, the code compares each character to see if it's a lowercase, uppercase, or not aA-zZ character and manipulates it by another variable of value 18.

I reassembled this into a script:

```
enc = "ZLT{Svvafy_kdwwhk_lg_qgmj_ugvw_escwk_al_wskq_lg_ghlaearw_dslwj!}"
flag = ""
for c in enc:
    some_var = 18
    asc = ord(c)
    if asc <= 96 or asc > 122:
        if asc <= 64 or asc > 90:   # not good
            flag += chr(asc)
            continue
        else:   # uppercase
            if asc - 18 <= 64:
                asc += 26
        asc -= 18
    else:   # lowercase
        if asc - some_var <= 96:
            asc += 26
        asc -= some_var
    flag += chr(asc)

print(flag)
```

The output (and flag) is `HTB{Adding_sleeps_to_your_code_makes_it_easy_to_optimize_later!}`


