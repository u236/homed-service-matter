#ifndef SESSION_H
#define SESSION_H

#include <QObject>
#include <QMap>
#include <QHostAddress>
#include "crypto.h"

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

    SessionInfo(void) : localSessionId(0), peerSessionId(0), peerPort(0), peerNodeId(0), localMessageCounter(0), active(false) {}
};

class SessionManager : public QObject
{
    Q_OBJECT

public:

    SessionManager(QObject *parent);

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

#endif
