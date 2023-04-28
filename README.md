# HPKE Example Programs

## How to Use

0. Build

```sh
make
```

1. Make reciever's public key.

```sh
./recieve -k
```

`reciever.pub` will generate.


2. Send a message.

```sh
./send
```

`ephemeral.pub` and `cipher_text.dat` will generate.

3. recieve a message.

```sh
./recieve -r
```

Now, maybe occur Segmentation fault (core dumped).

4. reset

```sh
make clean
```
