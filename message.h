#ifndef MESSAGE_H
#define MESSAGE_H

#include <QByteArray>
#include <QHostAddress>

/*
    Matter Message Format (spec section 4.4):

    Message Header:
    +--------+--------+--------+--------+
    | Flags  | Session ID      | Security
    +--------+--------+--------+--------+
    | Message Counter (4 bytes)          |
    +--------+--------+--------+--------+
    | Source Node ID (8 bytes, optional) |
    +--------+--------+--------+--------+
    | Dest Node ID (8 bytes, optional)   |
    +--------+--------+--------+--------+

    Message Flags (8 bits):
    - bits 0-1: version (0x00)
    - bit 2:    source node ID present (S flag)
    - bit 3:    reserved
    - bits 4-5: destination node ID type (DSIZ)
                00 = not present
                01 = 64-bit node ID
                10 = 16-bit group ID
                11 = reserved
    - bits 6-7: reserved

    Security Flags (8 bits):
    - bit 0:    privacy flag (P)
    - bit 1:    control message flag (C)
    - bit 2:    message extensions flag (MX)
    - bits 3-4: reserved
    - bits 5-7: session type
                00 = unicast
                01 = group

    Protocol Header (payload, after decryption for encrypted sessions):
    +--------+--------+--------+--------+
    | Exchange Flags  | Protocol OpCode  |
    +--------+--------+--------+--------+
    | Exchange ID     | Protocol ID      |
    +--------+--------+--------+--------+
    | Protocol Vendor ID (optional)      |
    +--------+--------+--------+--------+
    | Ack Counter (4 bytes, optional)    |
    +--------+--------+--------+--------+
*/

namespace MatterProtocol
{
    enum class SessionType : quint8
    {
        Unicast          = 0x00,
        Group            = 0x01
    };

    enum class SecurityFlag : quint8
    {
        Privacy          = 0x01,
        Control          = 0x02,
        Extensions       = 0x04
    };

    enum class ExchangeFlag : quint8
    {
        Initiator        = 0x01,
        Acknowledgement  = 0x02,
        Reliability      = 0x04,
        SecuredExtension = 0x08,
        Vendor           = 0x10
    };

    enum class ProtocolId : quint16
    {
        SecureChannel    = 0x0000,
        InteractionModel = 0x0001
    };

    enum class SecureChannelOpcode : quint8
    {
        MsgCounterSyncReq   = 0x00,
        MsgCounterSyncRsp   = 0x01,
        MRPStandaloneAck    = 0x10,
        PBKDFParamRequest   = 0x20,
        PBKDFParamResponse  = 0x21,
        PASEPake1            = 0x22,
        PASEPake2            = 0x23,
        PASEPake3            = 0x24,
        CASESigma1           = 0x30,
        CASESigma2           = 0x31,
        CASESigma3           = 0x32,
        CASESigma2Resume     = 0x33,
        StatusReport         = 0x40
    };

    enum class InteractionModelOpcode : quint8
    {
        StatusResponse       = 0x01,
        ReadRequest          = 0x02,
        SubscribeRequest     = 0x03,
        SubscribeResponse    = 0x04,
        ReportData           = 0x05,
        WriteRequest         = 0x06,
        WriteResponse        = 0x07,
        InvokeRequest        = 0x08,
        InvokeResponse       = 0x09,
        TimedRequest         = 0x0A
    };

    struct MessageHeader
    {
        quint8 flags;
        quint8 securityFlags;
        quint16 sessionId;
        quint32 messageCounter;
        quint64 sourceNodeId;
        quint64 destNodeId;
        quint16 destGroupId;

        quint8 version(void) const { return (flags >> 4) & 0x0F; }
        bool hasSourceNodeId(void) const { return flags & 0x04; }
        quint8 destIdType(void) const { return flags & 0x03; }
        SessionType sessionType(void) const { return static_cast <SessionType> ((securityFlags >> 5) & 0x03); }
        bool isControl(void) const { return securityFlags & static_cast <quint8> (SecurityFlag::Control); }
        bool hasExtensions(void) const { return securityFlags & static_cast <quint8> (SecurityFlag::Extensions); }

        MessageHeader(void) : flags(0), securityFlags(0), sessionId(0), messageCounter(0), sourceNodeId(0), destNodeId(0), destGroupId(0) {}
    };

    struct ProtocolHeader
    {
        quint8 exchangeFlags;
        quint8 opcode;
        quint16 exchangeId;
        quint16 protocolId;
        quint16 protocolVendorId;
        quint32 ackCounter;

        bool isInitiator(void) const { return exchangeFlags & static_cast <quint8> (ExchangeFlag::Initiator); }
        bool hasAck(void) const { return exchangeFlags & static_cast <quint8> (ExchangeFlag::Acknowledgement); }
        bool needsAck(void) const { return exchangeFlags & static_cast <quint8> (ExchangeFlag::Reliability); }
        bool hasVendor(void) const { return exchangeFlags & static_cast <quint8> (ExchangeFlag::Vendor); }

        ProtocolHeader(void) : exchangeFlags(0), opcode(0), exchangeId(0), protocolId(0), protocolVendorId(0), ackCounter(0) {}
    };

    struct MessageInfo
    {
        QHostAddress peerAddress;
        quint16 peerPort;
    };

    class MessageCodec
    {

    public:

        static bool decodeHeader(const QByteArray &data, MessageHeader &header, quint32 &offset);
        static bool decodeProtocolHeader(const QByteArray &data, quint32 offset, ProtocolHeader &header, quint32 &payloadOffset);

        static QByteArray encodeHeader(const MessageHeader &header);
        static QByteArray encodeProtocolHeader(const ProtocolHeader &header);
        static QByteArray encodeMessage(const MessageHeader &msgHeader, const ProtocolHeader &protoHeader, const QByteArray &payload);

    };
}

#endif
