# Custom TCP

This is the final project written as part of a Linux kernel development course.

It is a simplified implementation of the TCP protocol, allowing you to receive and send packets over established connections.

This code was written and tested for linux kernel version 6.19.8

## Building

For build this linux kernel module run:

```bash
KDIR=path/to/linux/source make
```

After building, you will have `my_tcp.ko` file

## Using

When the client accesses your computer to establish a connection, a device corresponding to the open connection will appear on your system in the `dev/mytcp` directory.

You can read the data transmitted by the client from this device or write it there to send a message to the client.
