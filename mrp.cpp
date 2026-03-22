#include "mrp.h"
#include "logger.h"
#include <QDateTime>
#include <QRandomGenerator>

#define COUNTER_WINDOW_SIZE 32

MRP::MRP(QObject *parent) : QObject(parent), m_timer(new QTimer(this)), m_debug(false)
{
    connect(m_timer, &QTimer::timeout, this, &MRP::processTimers);
    m_timer->start(50);
}

quint32 MRP::retransmitInterval(quint8 retryCount)
{
    double interval = MRP_RETRANS_BASE;

    for (quint8 i = 0; i < retryCount; i++)
        interval *= MRP_BACKOFF_MULTIPLIER;

    double jitter = interval * MRP_BACKOFF_JITTER * (QRandomGenerator::global()->generateDouble() * 2.0 - 1.0);
    return static_cast <quint32> (interval + jitter);
}

QString MRP::peerKey(const QHostAddress &address)
{
    return address.toString();
}

void MRP::messageSent(const QByteArray &data, const QHostAddress &address, quint16 port, quint32 messageCounter, quint16 exchangeId, bool needsAck)
{
    if (!needsAck)
        return;

    PendingMessage pending;
    pending.data = data;
    pending.address = address;
    pending.port = port;
    pending.messageCounter = messageCounter;
    pending.exchangeId = exchangeId;
    pending.retryCount = 0;
    pending.nextRetransmit = QDateTime::currentMSecsSinceEpoch() + retransmitInterval(0);

    m_pendingMessages.append(pending);
}

void MRP::messageReceived(quint32 messageCounter, quint16 exchangeId, bool hasAck, quint32 ackCounter, const QHostAddress &address, quint16 port, quint16 sessionId, bool needsAck, bool initiator)
{
    if (hasAck)
    {
        for (int i = m_pendingMessages.count() - 1; i >= 0; i--)
        {
            if (m_pendingMessages.at(i).messageCounter == ackCounter && m_pendingMessages.at(i).address == address)
            {
                m_pendingMessages.removeAt(i);
                break;
            }
        }
    }

    if (needsAck)
    {
        PendingAck ack;
        ack.address = address;
        ack.port = port;
        ack.sessionId = sessionId;
        ack.messageCounter = messageCounter;
        ack.exchangeId = exchangeId;
        ack.initiator = !initiator;
        ack.deadline = QDateTime::currentMSecsSinceEpoch() + MRP_STANDALONE_ACK_TIMEOUT;

        m_pendingAcks.append(ack);
    }

    QString key = peerKey(address);
    QList <quint32> &counters = m_peerCounters[key];
    counters.append(messageCounter);

    while (counters.count() > COUNTER_WINDOW_SIZE)
        counters.removeFirst();
}

bool MRP::isDuplicate(const QHostAddress &address, quint32 messageCounter)
{
    QString key = peerKey(address);

    if (!m_peerCounters.contains(key))
        return false;

    return m_peerCounters.value(key).contains(messageCounter);
}

void MRP::cancelPendingAck(quint32 messageCounter)
{
    for (int i = m_pendingAcks.count() - 1; i >= 0; i--)
    {
        if (m_pendingAcks.at(i).messageCounter == messageCounter)
        {
            m_pendingAcks.removeAt(i);
            break;
        }
    }
}

void MRP::processTimers(void)
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    for (int i = m_pendingAcks.count() - 1; i >= 0; i--)
    {
        const PendingAck &ack = m_pendingAcks.at(i);

        if (now >= ack.deadline)
        {
            quint32 messageCounter = ack.messageCounter;
            quint16 exchangeId = ack.exchangeId;
            quint16 sessionId = ack.sessionId;
            QHostAddress address = ack.address;
            quint16 port = ack.port;

            bool init = m_pendingAcks.at(i).initiator;
            m_pendingAcks.removeAt(i);
            emit sendStandaloneAck(messageCounter, exchangeId, sessionId, address, port, init);
        }
    }

    for (int i = m_pendingMessages.count() - 1; i >= 0; i--)
    {
        PendingMessage &pending = m_pendingMessages[i];

        if (now < pending.nextRetransmit)
            continue;

        pending.retryCount++;

        if (pending.retryCount > MRP_RETRANS_MAX)
        {
            logWarning << "MRP retransmit failed for counter" << pending.messageCounter;
            emit retransmitFailed(pending.messageCounter, pending.exchangeId, pending.address, pending.port);
            m_pendingMessages.removeAt(i);
            continue;
        }

        logDebug(m_debug) << "MRP retransmit" << pending.retryCount << "for counter" << pending.messageCounter;
        emit retransmit(pending.data, pending.address, pending.port);
        pending.nextRetransmit = now + retransmitInterval(pending.retryCount);
    }
}
