// NOT REWIEWED

#ifndef MRP_H
#define MRP_H

#define MRP_TIMER_INTERVAL          50
#define MRP_STANDALONE_ACK_TIMEOUT  200
#define MRP_RETRANSMIT_INTERVAL     300
#define MRP_RETRANSMIT_RETRIES      3
#define MRP_BACKOFF_MULTIPLIER      1.6
#define MRP_BACKOFF_JITTER          0.25
#define MRP_COUNTER_WINDOW_SIZE     32

#include <QHostAddress>
#include <QTimer>

struct PendingMessage
{
    QByteArray   data;
    QHostAddress address;
    quint16      port;
    quint32      messageCounter;
    quint16      exchangeId;
    quint8       retry;
    qint64       retransmitTime;
    quint32      interval;

    PendingMessage(void) : port(0), messageCounter(0), exchangeId(0), retry(0), retransmitTime(0), interval(0) {}
};

struct PendingAck
{
    QHostAddress address;
    quint16      port;
    quint16      sessionId;
    quint32      messageCounter;
    quint16      exchangeId;
    bool         initiator;
    qint64       deadline;

    PendingAck(void) : port(0), sessionId(0), messageCounter(0), exchangeId(0), initiator(false), deadline(0) {}
};

class MRP : public QObject
{
    Q_OBJECT

public:

    MRP(QObject *parent);

    inline void setDebug(bool value) { m_debug = value; }

    void messageSent(const QByteArray &data, const QHostAddress &address, quint16 port, quint32 messageCounter, quint16 exchangeId, bool needsAck, quint32 interval = 0);
    void messageReceived(quint32 messageCounter, quint16 exchangeId, bool hasAck, quint32 ackCounter, const QHostAddress &address, quint16 port, quint16 sessionId, bool needsAck, bool initiator);
    void cancelPendingAck(quint32 messageCounter);

    bool duplicate(const QHostAddress &address, quint32 messageCounter);

private:

    QTimer *m_timer;
    bool m_debug;

    QList <PendingMessage> m_pendingMessages;
    QList <PendingAck> m_pendingAcks;
    QMap <QString, QList <quint32>> m_counters;

    quint32 retransmitInterval(quint8 retry, quint32 interval);

private slots:

    void update(void);

signals:

    void retransmit(const QByteArray &data, const QHostAddress &address, quint16 port);
    void sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator);
    void retransmitFailed(quint32 messageCounter, quint16 exchangeId, const QHostAddress &address, quint16 port);

};

#endif
