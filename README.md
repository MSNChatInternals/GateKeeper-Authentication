## Background
MSN Chat used an authentication system known as GateKeeper, which evolved through three versions:
- **GateKeeper Version 1**: Utilized a simple hash of a nonce provided by the server.
- **GateKeeper Version 2**: Similar to version 1, but also sent a GUID to the server.
- **GateKeeper Version 3**: Similar to version 2, but required the client to append the server's hostname to the nonce before calculating the hash.

All three versions used the same hash calculation method and the same key.

There was also an extension to GateKeeper, known as GateKeeperPassport.
In this extension, the GUID that is sent in versions 2 and 3 would be set to `{00000000-0000-0000-0000-000000000000}`. Once the GateKeeper authentication was complete, the server would reply with "`OK`", prompting the client to then send the user's PassportTicket and PassportProfile cookies.
The server would verify the account was a valid Microsoft Account or MSA (previously known as Microsoft Passport, .NET Passport, and Windows Live ID) and set the user's address to an internal account identifier, rather than using the GUID as was done for regular GateKeeper users.

## Discovery Process
The [MSN Chat Protocol](MSN%20Chat%20Protocol.md) forum thread begins with a user wanting to connect to MSN Chat from a Linux environment. Another user, named zmic, started reverse engineering the MSN Chat Control to understand its workings. Through several attempts, zmic managed to authenticate successfully sometimes and eventually refined the method to work consistently (see [pyMSNChat](./pyMSNChat/)).

## Technical Details
The primary vulnerability in GateKeeper versions 1 and 2 was the omission of the server hostname in the hash. This allowed for a replay attack, where users could:
1. Connect to the MSN Chat Server using third-party software.
2. Load the official MSN Chat Control and have it connect to the third-party software.
3. Act as a proxy between the MSN Chat Control and the MSN Chat Server for each authentication message.
4. Destroy the MSN Chat Control once authentication was complete.

However, this method was limited to users who could load the MSN Chat Control, which was only possible on 32-bit Windows systems.

## GateKeeper Version 3
GateKeeper version 3 included the server hostname in the hash, making the previous replay attack method ineffective. However, several workarounds were developed:
- **M$NChatX by Matrix Team**: An alternative OCX modified to connect to localhost, regardless of the hostname provided. M$NChatX had a new GUID, allowing it to be installed alongside the official MSN Chat Control.
- **Ports of zmic's code**: Various ports of the code provided by zmic, including the updated hash calculation with the chat server's hostname.
- **Hooking wsock32.dll calls**: It was possible to hook various wsock32.dll calls to force connection to localhost or intercept the socket communication directly. This was demonstrated by JD long after the MSN Chat Service was closed.

By the time the MSN Chat Service closed, the most common method was to use ports of zmic's code with the updated algorithm. Many years later, JD noticed that the two keys provided by zmic's code were actually both 64-byte copies of the string "SRFMKSJANDRESKKC" XOR'd by 0x5c and 0x36, respectively. JD and Sky then realized that the authentication was based on a simple HMAC-MD5.

# GateKeeper Protocol Details

The GateKeeper protocol uses a specific signature and message structure to authenticate clients. Below are the detailed steps and examples of how the protocol works over the network.

### GateKeeper Signature and Header
- **Signature**: The GateKeeper signature is the null-terminated string "GKSSP".
- **Version and Sequence**: The GateKeeper version and the message sequence are represented as an `int32`.
- **Header Structure**: The GateKeeper header consists of:
  1. The GateKeeper signature.
  2. Two arbitrary bytes.
  3. The GateKeeper version.
  4. The message sequence.

### Protocol Steps
1. **Initial Client Message**: The client sends the header with sequence 1.
2. **Server Response**: The server replies with the header (sequence 2) followed by a nonce.
3. **Client Authentication**: The client calculates the HMAC-MD5 hash and sends back a header (sequence 3). For GateKeeper versions 2 and 3, the client also sends a GUID.

### Example Network Messages

#### Initial Client Message (Sequence 1)

Client -> Server: "GKSSP\0" + [two arbitrary bytes] + [version] + [sequence 1]

```
GKSSP\0\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00
```

#### Server Response (Sequence 2)

Server -> Client: "GKSSP\0" + [two arbitrary bytes] + [version] + [sequence 2] + [nonce]

```
GKSSP\0\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00 + [nonce]
```

#### Client Authentication (Sequence 3)

Client -> Server: "GKSSP\0" + [two arbitrary bytes] + [version] + [sequence 3] + [HMAC-MD5 hash] + [GUID (for v2 and v3)]

GateKeeper v1
```
GKSSP\0\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00 + [HMAC-MD5 hash]
```

GateKeeper v2 and v3
```
GKSSP\0\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00 + [HMAC-MD5 hash] + [GUID]
```

### Passport Extension

If the client requested to use GateKeeperPassport, the authentication continues as follows:

#### Server Acknowledgment

Server -> Client: "OK"

```
OK
```

#### Client Passport Information

Client -> Server: [length of PassportTicket in hex, zero-padded to 8] + [PassportTicket] + [length of PassportProfile in hex, zero-padded to 8] + [PassportProfile]

```
0000002B + [PassportTicket] + 0000003F + [PassportProfile]
```