# HPKE Example Programs

## How to Use

0. Build

```sh
make
```

1. Start the recieving program.

```sh
./recieve
Enter the message name you want to receive: 
```

`reciever.pub` will generate.  
Then, it enters the standard input waiting state.


2. Send a message in another terminal.

```sh
./send outMsg < inMsg.txt
```

Replace `inMsg.txt` with the text file path you want to send.  
`outMsg` is the message name. You can replace it with any string.

`outMsg.pub`(ephemeral public key) and `outMsg.enc`(cipher text) will generate.  


3. Enter the message name for the receiving program.

```sh
./recieve
Enter the message name you want to receive: outMsg
```

Then plain text is displayed.

4. reset

```sh
make clean
```
