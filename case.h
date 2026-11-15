// NOT REWIEWED

#ifndef CASE_H
#define CASE_H

#define SESSION_NONCE_LENGTH            13
#define SESSION_TAG_LENGTH              16

#define SESSION_IDLE_INTERVAL           500
#define SESSION_ACTIVE_INTERVAL         300
#define SESSION_ACTIVE_THRESHOLD        4000

#define CASE_TIMEOUT                    10000

#include <QHostAddress>
#include <QMap>
#include <QTimer>
#include "tlv.h"

struct SessionInfo
{
    quint16      localSessionId;
    quint16      peerSessionId;

    QByteArray   i2rKey;
    QByteArray   r2iKey;
    QByteArray   attestationChallenge;

    QHostAddress peerAddress;
    quint16      peerPort;

    quint64      peerNodeId;
    quint32      localMessageCounter;

    bool         active;
    bool         resumptionPending;

    quint32      idleInterval;
    quint32      activeInterval;
    quint16      activeThreshold;

    SessionInfo(void) : localSessionId(0), peerSessionId(0), peerPort(0), peerNodeId(0), localMessageCounter(0), active(false), resumptionPending(false), idleInterval(SESSION_IDLE_INTERVAL), activeInterval(SESSION_ACTIVE_INTERVAL), activeThreshold(SESSION_ACTIVE_THRESHOLD) {}
};

class SessionManager : public QObject
{
    Q_OBJECT

public:

    SessionManager(QObject *parent) : QObject(parent) {}

    void addSession(const SessionInfo &session);
    void removeSession(quint16 localSessionId);

    SessionInfo *byLocalId(quint16 localSessionId);
    SessionInfo *byPeerAddress(const QHostAddress &address, quint16 port);
    SessionInfo *byPeerNodeId(quint64 nodeId);

    static QByteArray nonce(quint8 securityFlags, quint32 messageCounter, quint64 sourceNodeId);
    QByteArray decrypt(SessionInfo *session, quint8 securityFlags, quint32 messageCounter, const QByteArray &header, const QByteArray &data);

private:

    QMap <quint16, SessionInfo> m_sessions;

};

class CASESession : public QObject
{
    Q_OBJECT

public:

    enum class State
    {
        Idle,
        WaitingSigma2,
        WaitingStatusReport,
        Established,
        Failed
    };

    CASESession(QObject *parent);

    inline quint32 peerMessageCounter(void) { return m_peerMessageCounter; }
    inline void setPeerMessageCounter(quint32 value) { m_peerMessageCounter = value; }

    inline QByteArray encryptKey(void) { return m_encryptKey; }
    inline QByteArray decryptKey(void) { return m_decryptKey; }
    inline QByteArray attestationChallenge(void) { return m_attestationChallenge; }

    inline QByteArray sharedSecret(void) { return m_sharedSecret; }
    inline QByteArray resumptionId(void) { return m_newResumptionId; }
    inline bool resumed(void) { return m_resumed; }

    inline quint32 idleInterval(void) { return m_idleInterval; }
    inline quint32 activeInterval(void) { return m_activeInterval; }
    inline quint16 activeThreshold(void) { return m_activeThreshold; }

    void start(quint16 localSessionId, quint64 peerNodeId, quint64 fabricId, const QByteArray &fabricPublicKey, const QByteArray &operationalKey, const QByteArray &ipk, const QByteArray &noc, const QByteArray &resumptionId, const QByteArray &resumptionSecret);

    void parseSigma2(const QByteArray &payload);
    void parseSigma2Resume(const QByteArray &payload);
    void parseStatusReport(const QByteArray &payload);

private:

    QTimer *m_timer;
    State m_state;

    quint16 m_localSessionId, m_peerSessionId;
    quint64 m_peerNodeId, m_fabricId;
    quint32 m_peerMessageCounter;

    QByteArray m_fabricPublicKey, m_operationalKey, m_ipk, m_noc;
    QByteArray m_initiatorRandom, m_privateKey, m_publicKey, m_sharedSecret, m_transcript;
    QByteArray m_encryptKey, m_decryptKey, m_attestationChallenge;

    QByteArray m_resumptionId, m_resumptionSecret, m_newResumptionId;
    bool m_resumed;

    quint32 m_idleInterval, m_activeInterval;
    quint16 m_activeThreshold;

    QByteArray destinationId(void);
    void parseSessionParameters(const MatterTLV::Element &element);
    void setSessionKeys(const QByteArray &data);
    void fail(const QString &reason);

private slots:

    void timeout(void);

signals:

    void sendSigma1(const QByteArray &payload);
    void sendSigma3(const QByteArray &payload);
    void established(quint16 localSessionId, quint16 peerSessionId);
    void failed(const QString &reason);

};

#endif
