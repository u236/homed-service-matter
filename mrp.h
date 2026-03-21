#ifndef MRP_H
#define MRP_H

#include <QObject>
#include <QTimer>
#include <QMap>
#include <QHostAddress>
#include "message.h"

/*
    Message Reliability Protocol (MRP) — spec section 4.11

    Provides reliable delivery over UDP:
    - Each message with R flag set requires an ACK
    - ACK via standalone ack or piggybacked in next message
    - Retransmit with exponential backoff
    - Duplicate detection via message counter tracking

    Timers:
    - MRP_STANDALONE_ACK_TIMEOUT: 200ms (max delay before sending standalone ACK)
    - MRP_RETRANS_BASE: 300ms (base retransmission interval)
    - MRP_RETRANS_MAX: 3 retries
    - MRP_BACKOFF_BASE: 1.6 (exponential backoff multiplier)
    - MRP_BACKOFF_JITTER: 0.25 (random jitter)
*/

#define MRP_STANDALONE_ACK_TIMEOUT  200
#define MRP_RETRANS_BASE            300
#define MRP_RETRANS_MAX             3
#define MRP_BACKOFF_MULTIPLIER      1.6
#define MRP_BACKOFF_JITTER          0.25

class MRP : public QObject
{
    Q_OBJECT

public:

    struct PendingMessage
    {
        QByteArray data;
        QHostAddress address;
        quint16 port;
        quint32 messageCounter;
        quint16 exchangeId;
        quint8 retryCount;
        qint64 nextRetransmit;

        PendingMessage(void) : port(0), messageCounter(0), exchangeId(0), retryCount(0), nextRetransmit(0) {}
    };

    struct PendingAck
    {
        QHostAddress address;
        quint16 port;
        quint16 sessionId;
        quint32 messageCounter;
        quint16 exchangeId;
        qint64 deadline;

        PendingAck(void) : port(0), sessionId(0), messageCounter(0), exchangeId(0), deadline(0) {}
    };

    MRP(QObject *parent);

    void messageSent(const QByteArray &data, const QHostAddress &address, quint16 port, quint32 messageCounter, quint16 exchangeId, bool needsAck);
    void messageReceived(quint32 messageCounter, quint16 exchangeId, bool hasAck, quint32 ackCounter, const QHostAddress &address, quint16 port, quint16 sessionId, bool needsAck);
    void cancelPendingAck(quint32 messageCounter);

    bool isDuplicate(const QHostAddress &address, quint32 messageCounter);

private:

    QTimer *m_timer;

    QList <PendingMessage> m_pendingMessages;
    QList <PendingAck> m_pendingAcks;
    QMap <QString, QList <quint32>> m_peerCounters;

    quint32 retransmitInterval(quint8 retryCount);
    QString peerKey(const QHostAddress &address);

private slots:

    void processTimers(void);

signals:

    void retransmit(const QByteArray &data, const QHostAddress &address, quint16 port);
    void sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port);
    void retransmitFailed(quint32 messageCounter, quint16 exchangeId);

};

#endif
