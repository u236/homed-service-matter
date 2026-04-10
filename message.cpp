// NOT REWIEWED

#include <QtEndian>
#include "message.h"

using namespace MatterProtocol;

static quint8 readU8(const QByteArray &data, quint32 &offset)
{
    if (offset >= static_cast <quint32> (data.length()))
        return 0;

    return static_cast <quint8> (data.at(offset++));
}

static quint16 readU16(const QByteArray &data, quint32 &offset)
{
    if (offset + 2 > static_cast <quint32> (data.length()))
        return 0;

    quint16 value = qFromLittleEndian <quint16> (data.constData() + offset);
    offset += 2;
    return value;
}

static quint32 readU32(const QByteArray &data, quint32 &offset)
{
    if (offset + 4 > static_cast <quint32> (data.length()))
        return 0;

    quint32 value = qFromLittleEndian <quint32> (data.constData() + offset);
    offset += 4;
    return value;
}

static quint64 readU64(const QByteArray &data, quint32 &offset)
{
    if (offset + 8 > static_cast <quint32> (data.length()))
        return 0;

    quint64 value = qFromLittleEndian <quint64> (data.constData() + offset);
    offset += 8;
    return value;
}

static void writeU8(QByteArray &data, quint8 value)
{
    data.append(static_cast <char> (value));
}

static void writeU16(QByteArray &data, quint16 value)
{
    quint16 le = qToLittleEndian(value);
    data.append(reinterpret_cast <const char*> (&le), 2);
}

static void writeU32(QByteArray &data, quint32 value)
{
    quint32 le = qToLittleEndian(value);
    data.append(reinterpret_cast <const char*> (&le), 4);
}

static void writeU64(QByteArray &data, quint64 value)
{
    quint64 le = qToLittleEndian(value);
    data.append(reinterpret_cast <const char*> (&le), 8);
}

bool MessageCodec::decodeHeader(const QByteArray &data, MessageHeader &header, quint32 &offset)
{
    offset = 0;

    if (data.length() < 8)
        return false;

    header.flags = readU8(data, offset);
    header.sessionId = readU16(data, offset);
    header.securityFlags = readU8(data, offset);
    header.messageCounter = readU32(data, offset);

    if (header.version() != 0x00)
        return false;

    if (header.hasSourceNodeId())
    {
        if (offset + 8 > static_cast <quint32> (data.length()))
            return false;

        header.sourceNodeId = readU64(data, offset);
    }

    switch (header.destIdType())
    {
        case 0x01:

            if (offset + 8 > static_cast <quint32> (data.length()))
                return false;

            header.destNodeId = readU64(data, offset);
            break;

        case 0x02:

            if (offset + 2 > static_cast <quint32> (data.length()))
                return false;

            header.destGroupId = readU16(data, offset);
            break;
    }

    if (header.hasExtensions())
    {
        if (offset + 2 > static_cast <quint32> (data.length()))
            return false;

        quint16 extLength = readU16(data, offset);

        if (offset + extLength > static_cast <quint32> (data.length()))
            return false;

        offset += extLength;
    }

    return true;
}

bool MessageCodec::decodeProtocolHeader(const QByteArray &data, quint32 offset, ProtocolHeader &header, quint32 &payloadOffset)
{
    if (offset + 6 > static_cast <quint32> (data.length()))
        return false;

    header.exchangeFlags = readU8(data, offset);
    header.opcode = readU8(data, offset);
    header.exchangeId = readU16(data, offset);
    header.protocolId = readU16(data, offset);

    if (header.hasVendor())
    {
        if (offset + 2 > static_cast <quint32> (data.length()))
            return false;

        header.protocolVendorId = readU16(data, offset);
    }

    if (header.hasAck())
    {
        if (offset + 4 > static_cast <quint32> (data.length()))
            return false;

        header.ackCounter = readU32(data, offset);
    }

    payloadOffset = offset;
    return true;
}

QByteArray MessageCodec::encodeHeader(const MessageHeader &header)
{
    QByteArray data;

    writeU8(data, header.flags);
    writeU16(data, header.sessionId);
    writeU8(data, header.securityFlags);
    writeU32(data, header.messageCounter);

    if (header.flags & 0x04)
        writeU64(data, header.sourceNodeId);

    switch (header.flags & 0x03)
    {
        case 0x01: writeU64(data, header.destNodeId); break;
        case 0x02: writeU16(data, header.destGroupId); break;
    }

    return data;
}

QByteArray MessageCodec::encodeProtocolHeader(const ProtocolHeader &header)
{
    QByteArray data;

    writeU8(data, header.exchangeFlags);
    writeU8(data, header.opcode);
    writeU16(data, header.exchangeId);
    writeU16(data, header.protocolId);

    if (header.exchangeFlags & static_cast <quint8> (ExchangeFlag::Vendor))
        writeU16(data, header.protocolVendorId);

    if (header.exchangeFlags & static_cast <quint8> (ExchangeFlag::Acknowledgement))
        writeU32(data, header.ackCounter);

    return data;
}

QByteArray MessageCodec::encodeMessage(const MessageHeader &msgHeader, const ProtocolHeader &protoHeader, const QByteArray &payload)
{
    QByteArray data = encodeHeader(msgHeader);
    data.append(encodeProtocolHeader(protoHeader));
    data.append(payload);
    return data;
}
