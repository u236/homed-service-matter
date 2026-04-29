// NOT REWIEWED

#ifndef CASE_H
#define CASE_H

#include <QHostAddress>
#include <QTimer>

/*
    Session Manager — tracks active Matter sessions (PASE and CASE).

    Each session has:
    - Local and peer session IDs
    - I2R (initiator-to-responder) and R2I (responder-to-initiator) keys
    - Message counters for nonce generation
    - Peer address/port

    Message encryption uses AES-128-CCM with:
    - Key: I2R or R2I depending on direction
    - Nonce: 13 bytes = flags(1) + messageCounter(4) + sourceNodeId(8)
    - AAD: message header bytes (everything before encrypted payload)
    - Tag: 16 bytes
*/

#define SESSION_NONCE_LENGTH    13
#define SESSION_TAG_LENGTH      16

struct SessionInfo
{
    quint16 localSessionId;
    quint16 peerSessionId;

    QByteArray i2rKey;  // encrypt key (we are initiator)
    QByteArray r2iKey;  // decrypt key
    QByteArray attestationChallenge;

    QHostAddress peerAddress;
    quint16 peerPort;

    quint64 peerNodeId;
    quint32 localMessageCounter;

    bool active;
    qint64 lastSeen;

    // peer-announced MRP timeouts from SessionParameters TLV in Sigma1/Sigma2 (Matter §4.11.2.2.1, milliseconds)
    quint32 idleInterval;
    quint32 activeInterval;
    quint16 activeThreshold;

    SessionInfo(void) : localSessionId(0), peerSessionId(0), peerPort(0), peerNodeId(0), localMessageCounter(0), active(false), lastSeen(0), idleInterval(500), activeInterval(300), activeThreshold(4000) {}
};

class SessionManager : public QObject
{
    Q_OBJECT

public:

    SessionManager(QObject *parent) : QObject(parent) {}

    void addSession(const SessionInfo &session);
    void removeSession(quint16 localSessionId);

    SessionInfo *findByLocalId(quint16 localSessionId);
    SessionInfo *findByPeerAddress(const QHostAddress &address, quint16 port);
    SessionInfo *findByPeerNodeId(quint64 nodeId);

    static QByteArray buildNonce(quint8 securityFlags, quint32 messageCounter, quint64 sourceNodeId);
    QByteArray encrypt(SessionInfo *session, const QByteArray &header, const QByteArray &payload);
    QByteArray decrypt(SessionInfo *session, quint8 securityFlags, quint32 messageCounter, quint64 sourceNodeId, const QByteArray &header, const QByteArray &ciphertext);

private:

    QMap <quint16, SessionInfo> m_sessions;

};

/*
    CASE — Certificate Authenticated Session Establishment (Matter spec 4.13.2)

    Commissioner (initiator) flow:
    1. Send Sigma1 → destinationId, ephPubKey
    2. Receive Sigma2 ← responderRandom, responderEphPubKey, encrypted2(NOC, signature)
    3. Send Sigma3 → encrypted3(NOC, signature)
    4. Receive StatusReport ← session established

    Key derivation uses ECDH shared secret + transcript hash (running SHA-256 of Sigma messages).
*/

#define CASE_TIMEOUT 10000

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

    void start(quint16 localSessionId, quint64 peerNodeId,
               const QByteArray &fabricKey, const QByteArray &fabricPublicKey,
               const QByteArray &operationalKey, const QByteArray &operationalPubKey,
               quint64 fabricId, quint64 nodeId, quint64 rootCAId,
               const QByteArray &ipk,
               const QByteArray &nocTLV, const QByteArray &rcacTLV,
               const QByteArray &resumptionID = QByteArray(), const QByteArray &resumptionSharedSecret = QByteArray());

    void handleSigma2(const QByteArray &payload);
    void handleSigma2Resume(const QByteArray &payload);
    void handleStatusReport(const QByteArray &payload);

    inline bool resumed(void) const { return m_resumed; }
    inline QByteArray newResumptionID(void) const { return m_newResumptionID; }
    inline QByteArray sharedSecret(void) const { return m_sharedSecret; }

    inline void setLastPeerMessageCounter(quint32 value) { m_lastPeerMessageCounter = value; }
    inline quint32 lastPeerMessageCounter(void) const { return m_lastPeerMessageCounter; }

    inline State state(void) const { return m_state; }
    inline quint16 localSessionId(void) const { return m_localSessionId; }
    inline quint16 peerSessionId(void) const { return m_peerSessionId; }

    inline QByteArray encryptKey(void) const { return m_encryptKey; }
    inline QByteArray decryptKey(void) const { return m_decryptKey; }
    inline QByteArray attestationChallenge(void) const { return m_attestationChallenge; }

    inline quint32 idleInterval(void) const { return m_idleInterval; }
    inline quint32 activeInterval(void) const { return m_activeInterval; }
    inline quint16 activeThreshold(void) const { return m_activeThreshold; }

private:

    State m_state;
    QTimer *m_timer;

    quint16 m_localSessionId;
    quint16 m_peerSessionId;
    quint64 m_peerNodeId;
    quint64 m_fabricId, m_nodeId, m_rootCAId;
    quint32 m_lastPeerMessageCounter;

    QByteArray m_fabricKey, m_fabricPublicKey;
    QByteArray m_operationalKey, m_operationalPubKey;
    QByteArray m_ipk;
    QByteArray m_nocTLV, m_rcacTLV;

    QByteArray m_initiatorRandom;
    QByteArray m_ephPrivKey, m_ephPubKey;
    QByteArray m_responderEphPubKey;
    QByteArray m_sharedSecret;

    // CASE session resumption (Matter §4.13.3)
    QByteArray m_resumptionID;            // ID we send in Sigma1 tag 6 (from previous CASE)
    QByteArray m_resumptionSharedSecret;  // shared secret from previous CASE, used for resume MIC + key derivation
    QByteArray m_newResumptionID;         // ID extracted from Sigma2 TBE2 tag 4 or Sigma2_Resume tag 1, persisted for next CASE
    bool m_resumed;

    // transcript hash (running SHA-256 of all Sigma messages)
    QByteArray m_sigma1Bytes;

    // session keys
    QByteArray m_encryptKey, m_decryptKey, m_attestationChallenge;

    // peer SessionParameters from Sigma2 (defaults per Matter §4.11.2.2.1)
    quint32 m_idleInterval;
    quint32 m_activeInterval;
    quint16 m_activeThreshold;

    QByteArray computeDestinationId(void);
    QByteArray transcriptHash(const QByteArray &data = QByteArray());

private slots:

    void timeout(void);

signals:

    void sendSigma1(const QByteArray &tlvPayload, quint16 localSessionId);
    void sendSigma3(const QByteArray &tlvPayload);
    void established(quint16 localSessionId, quint16 peerSessionId);
    void failed(const QString &reason);

};

#endif
