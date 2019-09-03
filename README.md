# SECIO Protocol Dissector

A Wireshark Lua plugin to dissect SECIO protocol packets with support of decryption. This plugin indended to run with go-libp2p-secio [fork](https://github.com/michaelvoronov/go-libp2p-secio) since it supports dumping secret symmetric keys. 

## Usage:
Copy the whole directory into your Wireshark `Personal Plugins` folder. To find out where it is located, open Wireshark and go to **Help->About Wireshark** and it will be listed in the **Folders** tab. You may need to create the folder the first time.

Another prerequisite is to define environment variable `LIBP2P_SECIO_KEYLOG` that should be pointer to the file with secret keys.

To run plugin you need to open Wireshark, sniff (or load from a dump) network traffic and then activate plugin via **Help->About Wireshark**.

![*Screenshot of plugin in use](https://raw.githubusercontent.com/michaelvoronov/secio-dissector/master/img/screen_1.png)

## Prerequisites

You need some lua packets installed:
   - ffi (`luarocks install --server=http://luarocks.org/dev luaffi`)
   - pb (`luarocks install lua-protobuf`) 
   - protoc (`luarocks install protoc`)
   - lua (`luarocks install csv`)
   - base64 (`luarocks install lbase64`)
   
Please be sure, that Wireshark has access to these plugins on your setup.
