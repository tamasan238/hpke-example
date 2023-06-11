# HPKE Example Programs

## How to Use

0. Build

```sh
make
```

1. Start the sending program.

```sh
./send
```

2. Start the receiving program in another terminal.

```sh
./receive
```

Then plain text is displayed.

3. reset

```sh
make clean
```

## How to Use (Old)

0. Build

```sh
make
```

1. Start the receiving program.

```sh
./receive
Enter the message name you want to receive: 
```

`receiver.pub` will generate.  
Then, it enters the standard input waiting state.


2. Send a message in another terminal.

```sh
./send outMsg
```

`outMsg` is the message name. You can replace it with any string.

`outMsg.pub`(ephemeral public key) and `outMsg.enc`(cipher text) will generate.  


3. Enter the message name for the receiving program.

```sh
./receive
Enter the message name you want to receive: outMsg
```

Then plain text is displayed.

4. reset

```sh
make clean
```
