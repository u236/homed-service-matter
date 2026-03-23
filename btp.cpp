#include "btp.h"
#include "logger.h"
#include <QtEndian>

BTP::BTP(QObject *parent) : QObject(parent), m_ready(false), m_ackPending(false), m_mtu(BTP_DEFAULT_MTU), m_windowSize(BTP_DEFAULT_WINDOW), m_txSequence(0), m_rxSequence(0), m_lastAck(0), m_rxExpectedLength(0)
{
}

void BTP::startHandshake(void)
{
    QByteArray packet;

    // flags: handshake + management + beginning + end
    packet.append(static_cast <char> (BTP_FLAG_HANDSHAKE | BTP_FLAG_MANAGEMENT | BTP_FLAG_BEGINNING | BTP_FLAG_END));

    // management opcode
    packet.append(static_cast <char> (BTP_HANDSHAKE_REQUEST));

    // supported versions bitmap (4 bytes LE, bit 2 = version 4)
    quint32 versions = qToLittleEndian <quint32> (1 << (BTP_VERSION - 2));
    packet.append(reinterpret_cast <const char*> (&versions), 4);

    // client MTU (little-endian) — 0 = use negotiated ATT_MTU
    quint16 mtu = 0;
    packet.append(reinterpret_cast <const char*> (&mtu), 2);

    // client window size
    packet.append(static_cast <char> (BTP_DEFAULT_WINDOW));

    logInfo << "BTP handshake request, MTU:" << BTP_DEFAULT_MTU << "window:" << BTP_DEFAULT_WINDOW;
    emit writeData(packet);
}

void BTP::handleData(const QByteArray &data)
{
    if (data.isEmpty())
        return;

    quint8 flags = static_cast <quint8> (data.at(0));
    int offset = 1;

    // handshake response: flags(1) + opcode(1) + version(1) + MTU(2) + windowSize(1) = 6 bytes
    if (flags & BTP_FLAG_HANDSHAKE)
    {
        if (data.size() < 6)
            return;

        quint8 version = static_cast <quint8> (data.at(2));
        m_mtu = qFromLittleEndian <quint16> (reinterpret_cast <const uchar*> (data.constData() + 3));
        m_windowSize = static_cast <quint8> (data.at(5));

        logInfo << "BTP handshake response, version:" << version << "MTU:" << m_mtu << "window:" << m_windowSize;

        m_ready = true;
        m_txSequence = 0;
        m_rxSequence = 0;
        m_lastAck = 0;

        emit handshakeComplete();
        return;
    }

    // ACK field
    if (flags & BTP_FLAG_ACK)
    {
        m_lastAck = static_cast <quint8> (data.at(offset));
        offset++;
    }

    // management-only packet (ACK only, no data)
    if (flags & BTP_FLAG_MANAGEMENT)
        return;

    // sequence number
    if (offset >= data.size())
        return;

    quint8 seq = static_cast <quint8> (data.at(offset));
    offset++;

    // beginning of new message
    if (flags & BTP_FLAG_BEGINNING)
    {
        if (offset + 2 > data.size())
            return;

        m_rxExpectedLength = qFromLittleEndian <quint16> (reinterpret_cast <const uchar*> (data.constData() + offset));
        offset += 2;

        m_rxBuffer.clear();
    }

    // append payload
    m_rxBuffer.append(data.mid(offset));
    m_rxSequence = seq;

    // end of message — deliver (ACK piggybacked in next outgoing message)
    if (flags & BTP_FLAG_END)
    {
        emit messageReceived(m_rxBuffer);
        m_rxBuffer.clear();
        m_rxExpectedLength = 0;
    }
}

void BTP::sendMessage(const QByteArray &message)
{
    if (!m_ready)
        return;

    sendSegments(message);
}

void BTP::sendSegments(const QByteArray &message)
{
    int maxPayload = m_mtu - 3; // flags + seq + overhead
    int offset = 0;
    bool first = true;

    while (offset < message.size())
    {
        QByteArray packet;
        quint8 flags = 0;
        int available = maxPayload;

        if (first)
        {
            flags |= BTP_FLAG_BEGINNING;
            available -= 2; // message length field
        }

        int remaining = message.size() - offset;
        int chunkSize = qMin(remaining, available);

        if (offset + chunkSize >= message.size())
            flags |= BTP_FLAG_END;

        // add ACK for last received sequence
        flags |= BTP_FLAG_ACK;

        packet.append(static_cast <char> (flags));

        // ACK number
        packet.append(static_cast <char> (m_rxSequence));

        // sequence number
        packet.append(static_cast <char> (m_txSequence++));

        // message length (only for first segment)
        if (first)
        {
            quint16 len = qToLittleEndian <quint16> (message.size());
            packet.append(reinterpret_cast <const char*> (&len), 2);
            first = false;
        }

        // payload
        packet.append(message.mid(offset, chunkSize));
        offset += chunkSize;

        emit writeData(packet);
    }
}

void BTP::sendAck(void)
{
    QByteArray packet;
    packet.append(static_cast <char> (BTP_FLAG_ACK));
    packet.append(static_cast <char> (m_rxSequence));
    emit writeData(packet);
}
