#include "session.h"
#include "logger.h"
#include <QtEndian>

SessionManager::SessionManager(QObject *parent) : QObject(parent)
{
}

void SessionManager::addSession(const SessionInfo &session)
{
    m_sessions.insert(session.localSessionId, session);
    logInfo << "Session added, local:" << session.localSessionId << "peer:" << session.peerSessionId << "address:" << session.peerAddress.toString() << ":" << session.peerPort;
}

void SessionManager::removeSession(quint16 localSessionId)
{
    m_sessions.remove(localSessionId);
}

SessionInfo *SessionManager::findByLocalId(quint16 localSessionId)
{
    if (!m_sessions.contains(localSessionId))
        return nullptr;

    return &m_sessions[localSessionId];
}

SessionInfo *SessionManager::findByPeerAddress(const QHostAddress &address, quint16 port)
{
    for (auto it = m_sessions.begin(); it != m_sessions.end(); it++)
    {
        if (it.value().peerAddress == address && it.value().peerPort == port && it.value().active)
            return &it.value();
    }

    return nullptr;
}

SessionInfo *SessionManager::findByPeerNodeId(quint64 nodeId)
{
    for (auto it = m_sessions.begin(); it != m_sessions.end(); it++)
    {
        if (it.value().peerNodeId == nodeId && it.value().active)
            return &it.value();
    }

    return nullptr;
}

QByteArray SessionManager::buildNonce(quint8 securityFlags, quint32 messageCounter, quint64 sourceNodeId)
{
    QByteArray nonce(SESSION_NONCE_LENGTH, 0);
    quint32 counterLE = qToLittleEndian(messageCounter);
    quint64 nodeLE = qToLittleEndian(sourceNodeId);

    nonce[0] = static_cast <char> (securityFlags);
    memcpy(nonce.data() + 1, &counterLE, 4);
    memcpy(nonce.data() + 5, &nodeLE, 8);

    return nonce;
}

QByteArray SessionManager::encrypt(SessionInfo *session, const QByteArray &header, const QByteArray &payload)
{
    QByteArray nonce = buildNonce(0x00, session->localMessageCounter, m_sessions.begin().value().peerNodeId);
    return Crypto::aesCcmEncrypt(session->i2rKey, nonce, header, payload, SESSION_TAG_LENGTH);
}

QByteArray SessionManager::decrypt(SessionInfo *session, quint8 securityFlags, quint32 messageCounter, quint64 sourceNodeId, const QByteArray &header, const QByteArray &ciphertext)
{
    QByteArray nonce = buildNonce(securityFlags, messageCounter, sourceNodeId);
    return Crypto::aesCcmDecrypt(session->r2iKey, nonce, header, ciphertext, SESSION_TAG_LENGTH);
}
