// NOT REWIEWED

#include <QtEndian>
#include "message.h"

using namespace MatterProtocol;

static bool readData(const QByteArray &data, quint32 &offset, void *value, size_t length)
{
    if (offset + length > static_cast <size_t> (data.length()))
        return false;

    memcpy(value, data.constData() + offset, length);
    offset += length;

    return true;
}

bool MessageCodec::decodeHeader(const QByteArray &data, MessageHeader &header, quint32 &offset)
{
    messageHeaderStruct message;

    offset = 0;

    if (!readData(data, offset, &message, sizeof(message)))
        return false;

    header.flags = message.flags;
    header.sessionId = qFromLittleEndian(message.sessionId);
    header.securityFlags = message.securityFlags;
    header.messageCounter = qFromLittleEndian(message.messageCounter);

    if (header.flags >> 4)
        return false;

    if (header.flags & MESSAGE_FLAG_SOURCE_NODE_ID)
    {
        if (!readData(data, offset, &header.sourceNodeId, sizeof(header.sourceNodeId)))
            return false;

        header.sourceNodeId = qFromLittleEndian(header.sourceNodeId);
    }

    switch (header.flags & MESSAGE_FLAG_DESTINATION_MASK)
    {
        case MESSAGE_DESTINATION_NODE_ID:

            if (!readData(data, offset, &header.destinationNodeId, sizeof(header.destinationNodeId)))
                return false;

            header.destinationNodeId = qFromLittleEndian(header.destinationNodeId);
            break;

        case MESSAGE_DESTINATION_GROUP_ID:

            if (!readData(data, offset, &header.destinationGroupId, sizeof(header.destinationGroupId)))
                return false;

            header.destinationGroupId = qFromLittleEndian(header.destinationGroupId);
            break;
    }

    if (header.securityFlags & static_cast <quint8> (SecurityFlag::Extensions))
    {
        quint16 length;

        if (!readData(data, offset, &length, sizeof(length)))
            return false;

        length = qFromLittleEndian(length);

        if (offset + length > static_cast <quint32> (data.length()))
            return false;

        offset += length;
    }

    return true;
}

bool MessageCodec::decodeProtocolHeader(const QByteArray &data, ProtocolHeader &header, quint32 &offset)
{
    protocolHeaderStruct protocol;

    offset = 0;

    if (!readData(data, offset, &protocol, sizeof(protocol)))
        return false;

    header.exchangeFlags = protocol.exchangeFlags;
    header.opcode = protocol.opcode;
    header.exchangeId = qFromLittleEndian(protocol.exchangeId);
    header.protocolId = qFromLittleEndian(protocol.protocolId);

    if (header.exchangeFlags & static_cast <quint8> (ExchangeFlag::Vendor))
    {
        if (!readData(data, offset, &header.vendorId, sizeof(header.vendorId)))
            return false;

        header.vendorId = qFromLittleEndian(header.vendorId);
    }

    if (header.exchangeFlags & static_cast <quint8> (ExchangeFlag::Acknowledgement))
    {
        if (!readData(data, offset, &header.ackCounter, sizeof(header.ackCounter)))
            return false;

        header.ackCounter = qFromLittleEndian(header.ackCounter);
    }

    return true;
}

QByteArray MessageCodec::encodeHeader(const MessageHeader &header)
{
    messageHeaderStruct message;
    QByteArray data;

    message.flags = header.flags;
    message.sessionId = qToLittleEndian(header.sessionId);
    message.securityFlags = header.securityFlags;
    message.messageCounter = qToLittleEndian(header.messageCounter);

    data = QByteArray(reinterpret_cast <char*> (&message), sizeof(message));

    if (header.flags & MESSAGE_FLAG_SOURCE_NODE_ID)
    {
        quint64 value = qToLittleEndian(header.sourceNodeId);
        data.append(reinterpret_cast <char*> (&value), sizeof(value));
    }

    switch (header.flags & MESSAGE_FLAG_DESTINATION_MASK)
    {
        case MESSAGE_DESTINATION_NODE_ID:
        {
            quint64 value = qToLittleEndian(header.destinationNodeId);
            data.append(reinterpret_cast <char*> (&value), sizeof(value));
            break;
        }

        case MESSAGE_DESTINATION_GROUP_ID:
        {
            quint16 value = qToLittleEndian(header.destinationGroupId);
            data.append(reinterpret_cast <char*> (&value), sizeof(value));
            break;
        }
    }

    return data;
}

QByteArray MessageCodec::encodeProtocolHeader(const ProtocolHeader &header)
{
    protocolHeaderStruct protocol;
    QByteArray data;

    protocol.exchangeFlags = header.exchangeFlags;
    protocol.opcode = header.opcode;
    protocol.exchangeId = qToLittleEndian(header.exchangeId);
    protocol.protocolId = qToLittleEndian(header.protocolId);

    data = QByteArray(reinterpret_cast <char*> (&protocol), sizeof(protocol));

    if (header.exchangeFlags & static_cast <quint8> (ExchangeFlag::Vendor))
    {
        quint16 value = qToLittleEndian(header.vendorId);
        data.append(reinterpret_cast <char*> (&value), sizeof(value));
    }

    if (header.exchangeFlags & static_cast <quint8> (ExchangeFlag::Acknowledgement))
    {
        quint32 value = qToLittleEndian(header.ackCounter);
        data.append(reinterpret_cast <char*> (&value), sizeof(value));
    }

    return data;
}

QByteArray MessageCodec::encodeMessage(const MessageHeader &messageHeader, const ProtocolHeader &protocolHeader, const QByteArray &payload)
{
    return encodeHeader(messageHeader).append(encodeProtocolHeader(protocolHeader)).append(payload);
}
