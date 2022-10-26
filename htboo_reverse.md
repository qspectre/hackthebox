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
