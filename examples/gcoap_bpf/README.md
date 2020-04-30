# BPF example application for RIOT

## About

This application provides a simple demonstrator for the rBPF virtual machine
implementation. It uses a gcoap server to provide CoAP capabilities which is
used both as transport for new rBPF programs and as a way to trigger the
execution of an rBPF program.

This example uses tap devices for networking on `native`, but should also
function on boards using ethos.

The relevant CoAP endpoints are `/bpf/handler` and `/bpf/submit`. The first
handler triggers the execution of the rBPF virtual machine with the loaded
program. The second handler allows for POST'ing a new program.

As this is a simple demonstrator, no security measures whatsoever are in place.
Do not expose this to public internet. You have been warned.

## Example use

On startup, no program is installed in the handler. To load and execute the
program, a number of steps are required. First the IPv6 address of the RIOT
instance needs to be known. Next, the rBPF program needs to be compiled. Then a
generic CoAP client has to be used to load the program on the RIOT instance.
Finally the program can be executed by requesting the CoAP endpoint using a CoAP
client.

This guide assumes a RIOT native instance with ethernet connectivity using TAP
devices. Start it using:

```
make term
```

### IPv6 address

The IPv6 address of the instance can be retrieved using the build-in shell:

```
> ifconfig
Iface  6  HWaddr: 3A:85:0B:F3:4B:63
          L2-PDU:1500 MTU:1500  HL:64  Source address length: 6
          Link type: wired
          inet6 addr: fe80::3885:bff:fef3:4b63  scope: link  VAL
          inet6 group: ff02::1
          inet6 group: ff02::1:fff3:4b63
```

### Compiling the rBPF program

A sample is provided in the bpf subdirectory of the example. It has a separate
makefile. The sample program formats a CoAP response with `hello` as content. It
can be compiled with:

```
make
```

It provides an object file and a raw binary file. The object file allows for
inspecting the resulting bytecode in a convenient way with

```
llvm-objdump -d sample_gcoap.o
```

The binary (`sample_gcoap.bin`) is the payload for the rBPF VM.
The binary blob can be compared with the dump from the object file using

```
xxd sample_gcoap.bin
```

### Transporting the bytecode

The resulting binary blob from the previous step can now be loaded in the RIOT
instance. Assuming coap-client from libcoap

```
coap-client -b64 -f sample_gcoap.bin -m post coap://[fe80::3885:bff:fef3:4b63%tapbr0]/bpf/submit
```

Note the block size (64 byte) and the method used. Also adapt the IPv6 address
to your local situation.

### Requesting the handler

The loaded program can now be triggered by:

```
coap-client coap://[fe80::3885:bff:fef3:4b63%tapbr0]/bpf/handle
```

With the default example, this returns `hello` as reply content.
