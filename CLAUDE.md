# homed-matter

Matter protocol controller for the HOMEd smart home system.

## Architecture

- **Controller** (`controller.h/cpp`) — main service class, inherits `HOMEd`, handles MQTT commands/events, device lifecycle, Home Assistant discovery
- **DeviceObject** (`device.h/cpp`) — Matter device model with nodeId, vendorId, productId; endpoints with exposes
- **DeviceList** — persistence to `/opt/homed-matter/database.json`, debounced writes
- **Matter** (`matter.h/cpp`) — Matter protocol stack: UDP transport, commissioning, interaction model
- **TLV** (`tlv.h/cpp`) — Matter TLV encoder/decoder (not ASN.1, Matter-specific format)

## Shared code

All HOMEd services share `homed-common` library:
- `HOMEd` base class — MQTT client, config, status, file I/O
- `AbstractDeviceObject` / `AbstractEndpointObject` — device/endpoint abstractions
- `ExposeObject` — Home Assistant discovery (switch, sensor, light, cover, thermostat, etc.)
- `main.cpp` — shared entry point with signal handling, lock file, restart loop
- Build includes: `homed-common.pri`, `homed-endpoint.pri`

## Build

```
qmake homed-matter.pro
make
```

Requires: Qt (mqtt, network modules), OpenSSL (libssl, libcrypto)

## Matter protocol layers (implementation roadmap)

1. **TLV** — encoding/decoding ✅ (basic implementation)
2. **UDP transport** — QUdpSocket ✅ (skeleton)
3. **Message framing** — Matter message header, exchange management
4. **MRP** — Message Reliability Protocol (ACK, retransmit)
5. **mDNS/DNS-SD** — device discovery via multicast UDP (224.0.0.251:5353)
6. **Secure Channel** — PASE (SPAKE2+ via OpenSSL) for commissioning, CASE (SIGMA) for sessions
7. **Interaction Model** — read/write/subscribe/invoke
8. **Data Model** — clusters (OnOff, LevelControl, ColorControl, etc.)
9. **Commissioning** — full flow: PASE → network config → NOC → CASE

## MQTT topics

Same pattern as other HOMEd services:
- `homed/command/matter` — commands (restartService, updateDevice, removeDevice, getProperties, permitJoin)
- `homed/td/matter/{device}/{endpoint}` — send commands to device
- `homed/fd/matter/{device}/{endpoint}` — device state feedback
- `homed/device/matter/{device}` — availability (online/offline)
- `homed/status/matter` — service status
- `homed/event/matter` — device events (added, updated, removed)

## Config

`/etc/homed/homed-matter.conf` (INI format, same structure as other services)

## Code style

- Qt/C++ with Q_OBJECT macros, signals/slots
- `inline` getters/setters in headers
- QSharedPointer typedefs: `Device`, `Endpoint`, `Expose`
- `logInfo`, `logWarning`, `logDebug` macros for logging
- `mqttSafe()` macro for sanitizing MQTT topic names
- No external Matter libraries — protocol implemented from scratch using OpenSSL for crypto primitives
