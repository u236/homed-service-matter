// NOT REWIEWED

#include <QtEndian>
#include "case.h"
#include "crypto.h"
#include "logger.h"
#include "message.h"

void SessionManager::addSession(const SessionInfo &session)
{
    m_sessions.insert(session.localSessionId, session);
    logInfo << "Session" << session.localSessionId << "added, peer session" << session.peerSessionId << "address" << session.peerAddress.toString() << "port" << session.peerPort;
}

void SessionManager::removeSession(quint16 localSessionId)
{
    m_sessions.remove(localSessionId);
}

SessionInfo *SessionManager::byLocalId(quint16 localSessionId)
{
    auto it = m_sessions.find(localSessionId);
    return it != m_sessions.end() ? &it.value() : nullptr;
}

SessionInfo *SessionManager::byPeerAddress(const QHostAddress &address, quint16 port)
{
    for (auto it = m_sessions.begin(); it != m_sessions.end(); it++)
    {
        if (!it.value().active || it.value().peerAddress != address || it.value().peerPort != port)
            continue;

        return &it.value();
    }

    return nullptr;
}

SessionInfo *SessionManager::byPeerNodeId(quint64 nodeId)
{
    for (auto it = m_sessions.begin(); it != m_sessions.end(); it++)
    {
        if (!it.value().active || it.value().peerNodeId != nodeId)
            continue;

        return &it.value();
    }

    return nullptr;
}

QByteArray SessionManager::nonce(quint8 securityFlags, quint32 messageCounter, quint64 sourceNodeId)
{
    messageCounter = qToLittleEndian(messageCounter);
    sourceNodeId = qToLittleEndian(sourceNodeId);
    return QByteArray(1, static_cast <char> (securityFlags)).append(reinterpret_cast <char*> (&messageCounter), sizeof(messageCounter)).append(reinterpret_cast <char*> (&sourceNodeId), sizeof(sourceNodeId));
}

QByteArray SessionManager::decrypt(SessionInfo *session, quint8 securityFlags, quint32 messageCounter, const QByteArray &header, const QByteArray &data)
{
    return Crypto::decrypt(session->r2iKey, nonce(securityFlags, messageCounter, session->peerNodeId), header, data, SESSION_TAG_LENGTH);
}

CASESession::CASESession(QObject *parent) : QObject(parent), m_timer(new QTimer(this)), m_state(State::Idle), m_localSessionId(0), m_peerSessionId(0), m_peerNodeId(0), m_fabricId(0), m_peerMessageCounter(0), m_resumed(false), m_idleInterval(SESSION_IDLE_INTERVAL), m_activeInterval(SESSION_ACTIVE_INTERVAL), m_activeThreshold(SESSION_ACTIVE_THRESHOLD)
{
    connect(m_timer, &QTimer::timeout, this, &CASESession::timeout);
    m_timer->setSingleShot(true);
}

void CASESession::start(quint16 localSessionId, quint64 peerNodeId, quint64 fabricId, const QByteArray &fabricPublicKey, const QByteArray &operationalKey, const QByteArray &ipk, const QByteArray &noc, const QByteArray &resumptionId, const QByteArray &resumptionSecret)
{
    MatterTLV::Encoder encoder;
    QByteArray compressedFabricId, mic;
    quint64 value = qToBigEndian(fabricId);
    bool resume = resumptionId.length() == 16 && resumptionSecret.length() == 32;

    m_localSessionId = localSessionId;
    m_peerNodeId = peerNodeId;
    m_fabricId = fabricId;
    m_fabricPublicKey = fabricPublicKey;
    m_operationalKey = operationalKey;
    m_noc = noc;
    m_resumptionId = resumptionId;
    m_resumptionSecret = resumptionSecret;
    m_newResumptionId.clear();
    m_resumed = false;

    compressedFabricId = Crypto::hkdf(m_fabricPublicKey.mid(1), QByteArray(reinterpret_cast <char*> (&value), sizeof(value)), "CompressedFabric", 8);
    m_ipk = Crypto::hkdf(ipk, compressedFabricId, "GroupKey v1.0", 16);

    m_initiatorRandom = Crypto::randomData(32);
    m_privateKey = Crypto::randomData(32);
    m_publicKey = ECPoint::multiply(ECPoint::generator(), BigNum(m_privateKey).bn()).toData();
    m_timer->start(CASE_TIMEOUT);

    if (resume)
        mic = Crypto::encrypt(Crypto::hkdf(m_resumptionSecret, QByteArray(m_initiatorRandom).append(m_resumptionId), "Sigma1_Resume", 16), QByteArray("NCASE_SigmaS1", 13), QByteArray(), QByteArray());

    encoder.openStructure();
    encoder.encodeByteString(1, m_initiatorRandom);
    encoder.encodeUnsignedInt(2, m_localSessionId);
    encoder.encodeByteString(3, destinationId());
    encoder.encodeByteString(4, m_publicKey);

    if (resume)
    {
        encoder.encodeByteString(6, m_resumptionId);
        encoder.encodeByteString(7, mic);
    }

    encoder.closeContainer();

    m_transcript = encoder.data();
    m_state = State::WaitingSigma2;

    logInfo << "CASE session" << m_localSessionId << "Sigma1 sent to node" << QString::number(m_peerNodeId, 16) << "with compressed fabric id" << compressedFabricId.toHex() << (resume ? "(resumption)" : "(full handshake)");
    emit sendSigma1(m_transcript);
}

void CASESession::parseSigma2(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    MatterTLV::Encoder tbs, tbe, sigma3;
    QByteArray random, publicKey, data, key, nonce("NCASE_Sigma3N", 13);
    ECPoint point;

    if (m_state != State::WaitingSigma2)
    {
        emit failed("Unexpected Sigma2");
        return;
    }

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        switch (item.tag)
        {
            case 1: random = item.value.toByteArray(); break;
            case 2: m_peerSessionId = static_cast <quint16> (item.value.toUInt()); break;
            case 3: publicKey = item.value.toByteArray(); break;
            case 4: data = item.value.toByteArray(); break;
            case 5: parseSessionParameters(item); break;
        }
    }

    logInfo << "CASE session" << m_localSessionId << "Sigma2 received, peer session" << m_peerSessionId << "idle interval" << m_idleInterval << "active interval" << m_activeInterval << "active threshold" << m_activeThreshold;

    if (publicKey.length() != 65 || data.isEmpty())
    {
        fail("Invalid Sigma2 data");
        return;
    }

    if (!point.fromData(publicKey))
    {
        fail("Invalid responder ephemeral public key");
        return;
    }

    // shared secret is X coordinate of ECDH result
    m_sharedSecret = ECPoint::multiply(point, BigNum(m_privateKey).bn()).toData().mid(1, 32);

    key = Crypto::hkdf(m_sharedSecret, QByteArray(m_ipk).append(random).append(publicKey).append(Crypto::sha256(m_transcript)), "Sigma2", 16);
    data = Crypto::decrypt(key, QByteArray("NCASE_Sigma2N", 13), QByteArray(), data);

    if (data.isEmpty())
    {
        fail("Sigma2 decryption failed");
        return;
    }

    // responder NOC and signature are not verified, only resumption id is taken from TBE2
    root = MatterTLV::Decoder(data).decode();

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        if (item.tag != 4 || item.type != MatterTLV::Type::ByteString)
            continue;

        m_newResumptionId = item.value.toByteArray();
    }

    m_transcript.append(payload);
    key = Crypto::hkdf(m_sharedSecret, QByteArray(m_ipk).append(Crypto::sha256(m_transcript)), "Sigma3", 16);

    tbs.openStructure();
    tbs.encodeByteString(1, m_noc);
    tbs.encodeByteString(3, m_publicKey);
    tbs.encodeByteString(4, publicKey);
    tbs.closeContainer();

    tbe.openStructure();
    tbe.encodeByteString(1, m_noc);
    tbe.encodeByteString(3, Crypto::sign(m_operationalKey, tbs.data()));
    tbe.closeContainer();

    sigma3.openStructure();
    sigma3.encodeByteString(1, Crypto::encrypt(key, nonce, QByteArray(), tbe.data()));
    sigma3.closeContainer();

    m_transcript.append(sigma3.data());
    setSessionKeys(Crypto::hkdf(m_sharedSecret, QByteArray(m_ipk).append(Crypto::sha256(m_transcript)), "SessionKeys", 48));
    m_state = State::WaitingStatusReport;

    logInfo << "CASE session" << m_localSessionId << "Sigma3 sent";
    emit sendSigma3(sigma3.data());
}

void CASESession::parseSigma2Resume(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    QByteArray resumptionId, mic;

    if (m_state != State::WaitingSigma2)
    {
        emit failed("Unexpected Sigma2_Resume");
        return;
    }

    if (m_resumptionSecret.length() != 32)
    {
        emit failed("Sigma2_Resume received without prior resumption secret");
        return;
    }

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        switch (item.tag)
        {
            case 1: resumptionId = item.value.toByteArray(); break;
            case 2: mic = item.value.toByteArray(); break;
            case 3: m_peerSessionId = static_cast <quint16> (item.value.toUInt()); break;
            case 4: parseSessionParameters(item); break;
        }
    }

    if (resumptionId.length() != 16 || mic.length() != 16)
    {
        fail("Invalid Sigma2_Resume data");
        return;
    }

    logInfo << "CASE session" << m_localSessionId << "Sigma2_Resume received, peer session" << m_peerSessionId << "idle interval" << m_idleInterval << "active interval" << m_activeInterval << "active threshold" << m_activeThreshold;

    // MIC salt uses new resumption id, session keys salt uses previous one (same as connectedhomeip)
    if (Crypto::encrypt(Crypto::hkdf(m_resumptionSecret, QByteArray(m_initiatorRandom).append(resumptionId), "Sigma2_Resume", 16), QByteArray("NCASE_SigmaS2", 13), QByteArray(), QByteArray()) != mic)
    {
        fail("Sigma2_Resume MIC verification failed");
        return;
    }

    setSessionKeys(Crypto::hkdf(m_resumptionSecret, QByteArray(m_initiatorRandom).append(m_resumptionId), "SessionResumptionKeys", 48));

    m_newResumptionId = resumptionId;
    m_sharedSecret = m_resumptionSecret;
    m_resumed = true;
    m_state = State::Established;
    m_timer->stop();

    logInfo << "CASE session" << m_localSessionId << "resumed with peer session" << m_peerSessionId;
    emit established(m_localSessionId, m_peerSessionId);
}

void CASESession::parseStatusReport(const QByteArray &payload)
{
    statusReportStruct report;

    if (static_cast <size_t> (payload.length()) < sizeof(report))
    {
        fail("Invalid StatusReport");
        return;
    }

    memcpy(&report, payload.constData(), sizeof(report));

    report.generalCode = qFromLittleEndian(report.generalCode);
    report.protocolId = qFromLittleEndian(report.protocolId);
    report.protocolCode = qFromLittleEndian(report.protocolCode);

    logInfo << "CASE session" << m_localSessionId << "StatusReport received, general code" << report.generalCode << "protocol" << report.protocolId << "code" << report.protocolCode;

    if (report.generalCode || report.protocolCode || m_state != State::WaitingStatusReport)
    {
        logWarning << "CASE session" << m_localSessionId << "failed with general code" << report.generalCode << "and protocol code" << report.protocolCode;
        fail(QString("CASE StatusReport error: general=%1 protocol=%2").arg(report.generalCode).arg(report.protocolCode));
        return;
    }

    m_state = State::Established;
    m_timer->stop();

    logInfo << "CASE session" << m_localSessionId << "established with peer session" << m_peerSessionId;
    emit established(m_localSessionId, m_peerSessionId);
}

QByteArray CASESession::destinationId(void)
{
    quint64 fabricId = qToLittleEndian(m_fabricId), nodeId = qToLittleEndian(m_peerNodeId);
    return Crypto::hmac(m_ipk, QByteArray(m_initiatorRandom).append(m_fabricPublicKey).append(reinterpret_cast <char*> (&fabricId), sizeof(fabricId)).append(reinterpret_cast <char*> (&nodeId), sizeof(nodeId)));
}

void CASESession::parseSessionParameters(const MatterTLV::Element &element)
{
    for (int i = 0; i < element.children.count(); i++)
    {
        const MatterTLV::Element &item = element.children.at(i);

        switch (item.tag)
        {
            case 1: m_idleInterval = item.value.toUInt(); break;
            case 2: m_activeInterval = item.value.toUInt(); break;
            case 3: m_activeThreshold = static_cast <quint16> (item.value.toUInt()); break;
        }
    }
}

void CASESession::setSessionKeys(const QByteArray &data)
{
    m_encryptKey = data.left(16);
    m_decryptKey = data.mid(16, 16);
    m_attestationChallenge = data.mid(32, 16);
}

void CASESession::fail(const QString &reason)
{
    m_state = State::Failed;
    emit failed(reason);
}

void CASESession::timeout(void)
{
    if (m_state == State::Established)
        return;

    logWarning << "CASE session" << m_localSessionId << "timed out";
    fail("CASE timeout");
}
