# GateKeeper Security Support Provider Interface Specification

## Abstract

This document specifies the GateKeeper Security Support Provider Interface (SSPI), a custom authentication protocol implementing challenge-response authentication using HMAC-MD5. The GateKeeper SSPI provides mutual authentication between clients and servers through a three-message exchange pattern, with support for multiple protocol versions offering varying security characteristics.

## Protocol Versioning

The GateKeeper SSPI supports four distinct protocol versions, each providing incremental security enhancements:

### Version 1
- **Authentication Method**: HMAC-MD5 over server-provided nonce
- **Client Identity**: Server assigns random GUID (GateKeeper ID) upon successful authentication
- **Security Properties**: Replay attack protection via server nonce

### Version 2  
- **Authentication Method**: HMAC-MD5 over server-provided nonce
- **Client Identity**: Client-provided GUID appended to authentication response
- **Security Properties**: Replay protection plus client identity assertion

### Version 3
- **Authentication Method**: HMAC-MD5 over concatenated nonce and target hostname
- **Client Identity**: Client-provided GUID appended to authentication response  
- **Security Properties**: Enhanced replay protection and server identity verification

### Version 4
- **Status**: Reserved for future use (no production deployment)

## Message Frame Structure

### Header Format
All GateKeeper SSPI protocol data units (PDUs) begin with a fixed 16-byte header conforming to the following structure:

```
Offset: 0       1       2       3       4       5       6       7
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |            "GKSSP" + NUL (6 bytes)            | Reserved (2)  |
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |       Version (4 bytes)       |         Sequence (4)          |
      +-------+-------+-------+-------+-------+-------+-------+-------+
```

**Field Definitions:**
- **Protocol Signature**: 6-byte ASCII string "GKSSP" followed by NULL terminator
- **Reserved**: 2-byte field, content undefined (typically uninitialized memory)
- **Version**: 32-bit unsigned integer specifying protocol version (1-4)
- **Sequence**: 32-bit unsigned integer indicating message type within authentication exchange

### Message Types
The Sequence field identifies the message's role in the authentication handshake:

| Value | Type | Direction | Description |
|-------|------|-----------|-------------|
| 1 | `INIT_REQUEST` | Client → Server | Initial authentication request |
| 2 | `CHALLENGE` | Server → Client | Server challenge with nonce |  
| 3 | `AUTH_RESPONSE` | Client → Server | Client authentication response |

## Authentication Protocol Exchange

The GateKeeper SSPI implements a three-phase challenge-response authentication mechanism conforming to standard SSPI multi-leg authentication patterns.

### Phase 1: Authentication Initiation
**Message Flow**: Client → Server  
**PDU Type**: `INIT_REQUEST` (Sequence = 1)  
**Payload**: None (header-only message)

The client initiates authentication by transmitting a header-only PDU specifying the desired protocol version. This message serves as both capability negotiation and session establishment.

### Phase 2: Server Challenge Generation  
**Message Flow**: Server → Client  
**PDU Type**: `CHALLENGE` (Sequence = 2)  
**Payload**: 8-byte cryptographic nonce

Upon receiving the client's authentication request, the server generates a cryptographically secure 8-byte nonce and transmits it to the client. This nonce provides replay attack mitigation and serves as input to the client's authentication proof.

### Phase 3: Client Authentication Response
**Message Flow**: Client → Server  
**PDU Type**: `AUTH_RESPONSE` (Sequence = 3)  
**Payload**: HMAC-MD5 authentication tag plus optional client identifier

The client computes an authentication tag using HMAC-MD5 and transmits it to the server for verification. Depending on the negotiated protocol version, additional client identification data may be appended to the response.

## Cryptographic Authentication Method

### HMAC-MD5 Computation
Client authentication employs HMAC-MD5 (RFC 2104) for message authentication code generation.

**Shared Secret**: 16-byte ASCII key `"SRFMKSJANDRESKKC"`  
**Note**: Original implementation employs obfuscation techniques to protect key material in memory.

### Version-Specific Authentication Data Construction

#### Version 1 Protocol
**HMAC Input**: `server_nonce`  
**Response Payload**: `hmac_md5_output`  
**Post-Authentication**: Server assigns random GUID (GateKeeper ID) to authenticated client

#### Version 2 Protocol  
**HMAC Input**: `server_nonce`  
**Response Payload**: `hmac_md5_output || client_guid`  
**Enhancement**: Client identity assertion through GUID transmission

#### Version 3 Protocol
**HMAC Input**: `server_nonce || target_hostname`  
**Response Payload**: `hmac_md5_output || client_guid`  
**Enhancement**: Server identity verification via hostname binding

#### Version 4 Protocol
**Status**: Reserved - no standardized implementation

### Authentication Response Structure
```
Offset: 0       1       2       3       4       5       6       7
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |                  HMAC-MD5 Output (16 bytes)                   |
      +-------+-------+-------+-------+-------+-------+-------+-------+
      |          Client GUID (16 bytes, Versions 2 & 3 only)          |
      +-------+-------+-------+-------+-------+-------+-------+-------+
```

## Windows SSPI Integration

### Security Package Registration
The GateKeeper SSPI integrates with the Windows Security Support Provider Interface through standard package registration mechanisms:

**Package Names**: 
- `"GateKeeper"` - Standard authentication package
<!-- - `"GateKeeperPassport"` - Microsoft Passport integration variant -->

**Package Capabilities**:
- `SECPKG_FLAG_TOKEN_ONLY` - Token-based authentication
- `SECPKG_FLAG_MULTI_REQUIRED` - Multi-message authentication sequence
- `SECPKG_FLAG_CONNECTION` - Connection-oriented security context

**Registry Configuration**: Package metadata and configuration parameters stored under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders`

## Implementation Requirements

### Security Considerations
**Key Material Protection**: The shared authentication key requires protection against memory disclosure attacks. Reference implementations employ runtime obfuscation including XOR encoding and offset-based access patterns.

**Nonce Generation**: Server nonce values MUST be cryptographically random with sufficient entropy (minimum 64 bits). Implementations SHOULD use platform cryptographic APIs (`CryptGenRandom`, `BCryptGenRandom`).

**Replay Attack Mitigation**: Server implementations MUST validate nonce uniqueness within reasonable time windows to prevent replay attacks.

### SSPI Compliance Requirements

#### Required Function Exports
- `InitializeSecurityContext` - Client-side context establishment
- `AcceptSecurityContext` - Server-side context acceptance  
- `QueryContextAttributes` - Security context introspection
- `DeleteSecurityContext` - Context cleanup and resource deallocation

#### Standard Return Codes
| Return Value | Meaning |
|--------------|---------|
| `SEC_E_OK` | Authentication completed successfully |
| `SEC_I_CONTINUE_NEEDED` | Additional authentication messages required |
| `SEC_E_INVALID_TOKEN` | Malformed or corrupted authentication token |
| `SEC_E_LOGON_DENIED` | Authentication verification failed |
| `SEC_E_INSUFFICIENT_MEMORY` | Memory allocation failure |

### Platform Compatibility
- **Target Platform**: Windows NT 4.0+ with SSPI support
- **Architecture**: x86, x64 native code execution
- **Dependencies**: Windows Authentication APIs, Registry access

## Binary Message Examples

### Client Initial Request (16 bytes):
```
47 4B 53 53 50 00 00 00 | "GKSSP\0" + padding
00 00 00 03 00 00 00 01 | version=3, sequence=1
```

### Server Challenge Response (24 bytes):
```
47 4B 53 53 50 00 00 00 | "GKSSP\0" + padding  
00 00 00 03 00 00 00 02 | version=3, sequence=2
[8_nonce_bytes...]      | 8-byte server-generated nonce
```

### Client Authentication (32 bytes for version 2 & 3):
```
47 4B 53 53 50 00 00 00 | "GKSSP\0" + padding
00 00 00 03 00 00 00 03 | version=3, sequence=3  
[hmac_md5_result...]    | 16-byte HMAC-MD5 hash
[client_guid...]        | 16-byte client GUID (version 2 & 3)
```

## References

- Windows SSPI Documentation
- Decompiled MSN Chat 4.5 implementation (`msnchat45.c`)
- Windows Security Package Interface specifications
