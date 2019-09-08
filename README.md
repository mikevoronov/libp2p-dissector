# Libp2p dissector

A Wireshark Lua plugin to dissect several libp2p protocols with support of SECIO decryption. This plugin indended to run with go-libp2p-secio [fork](https://github.com/michaelvoronov/go-libp2p-secio) since it supports dumping secret symmetric keys. 

## Usage:
Copy the whole directory into your Wireshark `Personal Plugins` folder. To find out where it is located, open Wireshark and go to **Help->About Wireshark** and it will be listed in the **Folders** tab. You may need to create the folder the first time.

Another prerequisite is to define environment variable `LIBP2P_SECIO_KEYLOG` that should be pointer to the file with secret keys.

To run plugin you need to open Wireshark, sniff (or load from a dump) network traffic and then activate plugin via **Help->About Wireshark**.

![*SECIO dissecting: example 1](https://raw.githubusercontent.com/michaelvoronov/secio-dissector/master/img/screen_1.png)

![*SECIO dissecting: example 2](https://raw.githubusercontent.com/michaelvoronov/secio-dissector/master/img/screen_2.png)

## Prerequisites

You need some lua packets installed:
   - ffi (`luarocks install --server=http://luarocks.org/dev luaffi`)
   - pb (`luarocks install lua-protobuf`) 
   - protoc (`luarocks install protoc`)
   - lua (`luarocks install csv`)
   - base64 (`luarocks install lbase64`)
   
Please be sure, that Wireshark has access to these plugins on your setup.

## Supported protocols

- [X] multistream 1.0.0
- [X] secio 1.0.0
- [X] mplex 1.0.0
- [ ] yamux
- [ ] spdy
- [ ] ipfs

## High-level dissecting algorithm overview

1. At first, multistream dissector is registred as the heuristic dissector
2. This dissecctor looks for the "/multistream/1.0.0" string in traffic, then parses multistream handshaked packets and, finally, calls secio dissector.
3. In its turn, secio dissector waits for Propose and Excahnge packets. And after receiving the last Exchange packet will try to open config file and try to find the last record for corresponding in/out ip:port. It is expected that after the last Exchange packet keys are already dumped.
4. And, finally, dissect mplex.