// NOT REWIEWED

#include <QDateTime>
#include <QRandomGenerator>
#include "logger.h"
#include "mrp.h"

MRP::MRP(QObject *parent) : QObject(parent), m_timer(new QTimer(this)), m_debug(false)
{
    connect(m_timer, &QTimer::timeout, this, &MRP::update);
    m_timer->start(MRP_TIMER_INTERVAL);
}

void MRP::messageSent(const QByteArray &data, const QHostAddress &address, quint16 port, quint32 messageCounter, quint16 exchangeId, bool needsAck, quint32 interval)
{
    PendingMessage message;
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    if (!needsAck)
        return;

    message.data = data;
    message.address = address;
    message.port = port;
    message.messageCounter = messageCounter;
    message.exchangeId = exchangeId;
    message.interval = interval;
    message.retransmitTime = now + retransmitInterval(0, interval);

    m_pendingMessages.append(message);
    logDebug(m_debug) << "MRP message" << messageCounter << "sent to" << address.toString() << "port" << port << "retransmit in" << message.retransmitTime - now << "ms, queue length" << m_pendingMessages.count();
}

void MRP::messageReceived(quint32 messageCounter, quint16 exchangeId, bool hasAck, quint32 ackCounter, const QHostAddress &address, quint16 port, quint16 sessionId, bool needsAck, bool initiator)
{
    QList <quint32> &counters = m_counters[address.toString()];

    if (hasAck)
    {
        for (int i = m_pendingMessages.count() - 1; i >= 0; i--)
        {
            const PendingMessage &message = m_pendingMessages.at(i);

            if (message.messageCounter != ackCounter || message.address != address)
                continue;

            logDebug(m_debug) << "MRP message" << ackCounter << "acknowledged by" << address.toString();
            m_pendingMessages.removeAt(i);
            break;
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

    counters.append(messageCounter);

    while (counters.count() > MRP_COUNTER_WINDOW_SIZE)
        counters.removeFirst();
}

void MRP::cancelPendingAck(quint32 messageCounter)
{
    for (int i = m_pendingAcks.count() - 1; i >= 0; i--)
    {
        if (m_pendingAcks.at(i).messageCounter != messageCounter)
            continue;

        m_pendingAcks.removeAt(i);
        break;
    }
}

bool MRP::duplicate(const QHostAddress &address, quint32 messageCounter)
{
    return m_counters.value(address.toString()).contains(messageCounter);
}

quint32 MRP::retransmitInterval(quint8 retry, quint32 interval)
{
    double value = interval ? interval : MRP_RETRANSMIT_INTERVAL;

    for (quint8 i = 0; i < retry; i++)
        value *= MRP_BACKOFF_MULTIPLIER;

    return static_cast <quint32> (value + value * MRP_BACKOFF_JITTER * (QRandomGenerator::global()->generateDouble() * 2 - 1));
}

void MRP::update(void)
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    for (int i = m_pendingAcks.count() - 1; i >= 0; i--)
    {
        PendingAck ack;

        if (now < m_pendingAcks.at(i).deadline)
            continue;

        ack = m_pendingAcks.takeAt(i);
        emit sendStandaloneAck(ack.messageCounter, ack.exchangeId, ack.sessionId, ack.address, ack.port, ack.initiator);
    }

    for (int i = m_pendingMessages.count() - 1; i >= 0; i--)
    {
        PendingMessage &message = m_pendingMessages[i];

        if (now < message.retransmitTime)
            continue;

        if (++message.retry > MRP_RETRANSMIT_RETRIES)
        {
            logWarning << "MRP message" << message.messageCounter << "retransmit failed";
            emit retransmitFailed(message.messageCounter, message.exchangeId, message.address, message.port);
            m_pendingMessages.removeAt(i);
            continue;
        }

        logDebug(m_debug) << "MRP message" << message.messageCounter << "retransmit" << message.retry;
        emit retransmit(message.data, message.address, message.port);
        message.retransmitTime = now + retransmitInterval(message.retry, message.interval);
    }
}
