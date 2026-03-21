#include "case.h"
#include "logger.h"
#include <QtEndian>

CASESession::CASESession(QObject *parent) : QObject(parent), m_state(State::Idle), m_timer(new QTimer(this)), m_localSessionId(0), m_peerSessionId(0), m_peerNodeId(0), m_fabricId(0), m_nodeId(0), m_rootCAId(0), m_lastPeerMessageCounter(0)
{
    connect(m_timer, &QTimer::timeout, this, &CASESession::timeout);
    m_timer->setSingleShot(true);
}

QByteArray CASESession::computeDestinationId(void)
{
    // destinationId = HMAC-SHA256(IPK, initiatorRandom || rootPubKey || fabricId_LE || nodeId_LE)
    QByteArray message;
    message.append(m_initiatorRandom);
    message.append(m_fabricPublicKey);  // root CA public key (65 bytes)

    quint64 fabricLE = qToLittleEndian(m_fabricId);
    quint64 nodeLE = qToLittleEndian(m_peerNodeId);
    message.append(reinterpret_cast <const char*> (&fabricLE), 8);
    message.append(reinterpret_cast <const char*> (&nodeLE), 8);

    return Crypto::hmacSha256(m_ipk, message);
}

QByteArray CASESession::transcriptHash(const QByteArray &data)
{
    QByteArray input = m_sigma1Bytes;

    if (!data.isEmpty())
        input.append(data);

    return Crypto::sha256(input);
}

void CASESession::start(quint16 localSessionId, quint64 peerNodeId,
                         const QByteArray &fabricKey, const QByteArray &fabricPublicKey,
                         const QByteArray &operationalKey, const QByteArray &operationalPubKey,
                         quint64 fabricId, quint64 nodeId, quint64 rootCAId,
                         const QByteArray &ipk,
                         const QByteArray &nocTLV, const QByteArray &rcacTLV)
{
    m_localSessionId = localSessionId;
    m_peerNodeId = peerNodeId;
    m_fabricKey = fabricKey;
    m_fabricPublicKey = fabricPublicKey;
    m_operationalKey = operationalKey;
    m_operationalPubKey = operationalPubKey;
    m_fabricId = fabricId;
    m_nodeId = nodeId;
    m_rootCAId = rootCAId;
    m_ipk = ipk;
    m_nocTLV = nocTLV;
    m_rcacTLV = rcacTLV;

    m_initiatorRandom = Crypto::randomBytes(32);
    m_timer->start(CASE_TIMEOUT);

    // generate ephemeral P-256 keypair
    m_ephPrivKey = Crypto::randomBytes(32);
    ECPoint ephPub = ECPoint::fromMultiply(ECPoint::generator(), BigNum(m_ephPrivKey).bn());
    m_ephPubKey = ephPub.toUncompressed();

    // build Sigma1 TLV
    MatterTLV::Encoder encoder;
    encoder.openStructure();
    encoder.encodeByteString(1, m_initiatorRandom);         // initiatorRandom
    encoder.encodeUnsignedInt(2, m_localSessionId);         // initiatorSessionId
    encoder.encodeByteString(3, computeDestinationId());    // destinationId
    encoder.encodeByteString(4, m_ephPubKey);               // initiatorEphPubKey
    encoder.closeContainer();

    m_sigma1Bytes = encoder.data();
    m_state = State::WaitingSigma2;

    logInfo << "CASE: sending Sigma1, sessionId:" << m_localSessionId;
    emit sendSigma1(m_sigma1Bytes, m_localSessionId);
}

void CASESession::handleSigma2(const QByteArray &payload)
{
    if (m_state != State::WaitingSigma2)
    {
        emit failed("Unexpected Sigma2");
        return;
    }

    MatterTLV::Decoder decoder(payload);
    MatterTLV::Element root = decoder.decode();

    QByteArray responderRandom, encrypted2;

    for (const MatterTLV::Element &el : root.children)
    {
        switch (el.tag)
        {
            case 1: responderRandom = el.value.toByteArray(); break;
            case 2: m_peerSessionId = el.value.toUInt(); break;
            case 3: m_responderEphPubKey = el.value.toByteArray(); break;
            case 4: encrypted2 = el.value.toByteArray(); break;
        }
    }

    logInfo << "CASE: Sigma2 received, peer session:" << m_peerSessionId;

    if (m_responderEphPubKey.length() != 65 || encrypted2.isEmpty())
    {
        m_state = State::Failed;
        emit failed("Invalid Sigma2 data");
        return;
    }

    // ECDH: shared secret = X-coordinate of (ephPrivKey * responderEphPubKey)
    ECPoint responderPoint;

    if (!responderPoint.setFromUncompressed(m_responderEphPubKey))
    {
        m_state = State::Failed;
        emit failed("Invalid responder ephemeral public key");
        return;
    }

    ECPoint sharedPoint = ECPoint::fromMultiply(responderPoint, BigNum(m_ephPrivKey).bn());
    QByteArray sharedUncompressed = sharedPoint.toUncompressed();
    m_sharedSecret = sharedUncompressed.mid(1, 32); // X-coordinate only

    // S2K: HKDF(sharedSecret, salt=IPK||responderRandom||responderEphPubKey||transcriptHash(Sigma1), info="Sigma2", 16)
    QByteArray s2kSalt;
    s2kSalt.append(m_ipk);
    s2kSalt.append(responderRandom);
    s2kSalt.append(m_responderEphPubKey);
    s2kSalt.append(transcriptHash()); // hash of Sigma1 only
    QByteArray s2k = Crypto::hkdfSha256(m_sharedSecret, s2kSalt, QByteArray("Sigma2"), 16);

    // decrypt TBE2
    QByteArray sigma2Nonce("NCASE_Sigma2N", 13);
    QByteArray tbe2 = Crypto::aesCcmDecrypt(s2k, sigma2Nonce, QByteArray(), encrypted2, 16);

    if (tbe2.isEmpty())
    {
        m_state = State::Failed;
        emit failed("Sigma2 decryption failed");
        return;
    }

    logInfo << "CASE: Sigma2 decrypted, TBE2 size:" << tbe2.size();

    // parse TBE2: tag 1 = responder NOC, tag 2 = responder ICAC (opt), tag 3 = signature
    // (we skip detailed verification for now)

    // update transcript with Sigma2 bytes (the full payload we received)
    m_sigma1Bytes.append(payload);

    // S3K: HKDF(sharedSecret, salt=IPK||transcriptHash(Sigma1+Sigma2), info="Sigma3", 16)
    QByteArray s3kSalt;
    s3kSalt.append(m_ipk);
    s3kSalt.append(transcriptHash()); // hash of Sigma1 + Sigma2
    QByteArray s3k = Crypto::hkdfSha256(m_sharedSecret, s3kSalt, QByteArray("Sigma3"), 16);

    // build TBS3 for signature: { NOC, ephPubKey, responderEphPubKey }
    MatterTLV::Encoder tbsEncoder;
    tbsEncoder.openStructure();
    tbsEncoder.encodeByteString(1, m_nocTLV);               // our NOC
    tbsEncoder.encodeByteString(3, m_ephPubKey);             // our ephemeral public key
    tbsEncoder.encodeByteString(4, m_responderEphPubKey);    // responder ephemeral public key
    tbsEncoder.closeContainer();

    QByteArray signature = Crypto::ecdsaSign(m_operationalKey, tbsEncoder.data());

    // build TBE3: { NOC, signature }
    MatterTLV::Encoder tbe3Encoder;
    tbe3Encoder.openStructure();
    tbe3Encoder.encodeByteString(1, m_nocTLV);    // our NOC
    tbe3Encoder.encodeByteString(3, signature);    // signature
    tbe3Encoder.closeContainer();

    // encrypt TBE3
    QByteArray sigma3Nonce("NCASE_Sigma3N", 13);
    QByteArray encrypted3 = Crypto::aesCcmEncrypt(s3k, sigma3Nonce, QByteArray(), tbe3Encoder.data(), 16);

    // build Sigma3 TLV
    MatterTLV::Encoder sigma3;
    sigma3.openStructure();
    sigma3.encodeByteString(1, encrypted3);
    sigma3.closeContainer();

    QByteArray sigma3Bytes = sigma3.data();

    // update transcript with Sigma3
    m_sigma1Bytes.append(sigma3Bytes);

    // derive session keys: HKDF(sharedSecret, salt=IPK||transcriptHash(all), info="SessionKeys", 48)
    QByteArray seKeysSalt;
    seKeysSalt.append(m_ipk);
    seKeysSalt.append(transcriptHash()); // hash of Sigma1 + Sigma2 + Sigma3
    QByteArray sessionKeys = Crypto::hkdfSha256(m_sharedSecret, seKeysSalt, QByteArray("SessionKeys"), 48);

    m_encryptKey = sessionKeys.left(16);
    m_decryptKey = sessionKeys.mid(16, 16);
    m_attestationChallenge = sessionKeys.mid(32, 16);

    m_state = State::WaitingStatusReport;

    logInfo << "CASE: sending Sigma3";
    emit sendSigma3(sigma3Bytes);
}

void CASESession::handleStatusReport(const QByteArray &payload)
{
    if (payload.length() < 8)
    {
        m_state = State::Failed;
        emit failed("Invalid StatusReport");
        return;
    }

    quint16 generalCode = qFromLittleEndian <quint16> (payload.constData());
    quint32 protocolId = qFromLittleEndian <quint32> (payload.constData() + 2);
    quint16 protocolCode = qFromLittleEndian <quint16> (payload.constData() + 6);

    logInfo << "CASE: StatusReport general:" << generalCode << "protocolId:" << protocolId << "protocolCode:" << protocolCode;

    if (generalCode == 0 && protocolCode == 0 && m_state == State::WaitingStatusReport)
    {
        m_state = State::Established;
        m_timer->stop();
        logInfo << "CASE: session established, local:" << m_localSessionId << "peer:" << m_peerSessionId;
        emit established(m_localSessionId, m_peerSessionId);
    }
    else
    {
        m_state = State::Failed;
        logWarning << "CASE: failed with general code:" << generalCode << "protocol code:" << protocolCode;
        emit failed(QString("CASE StatusReport error: general=%1 protocol=%2").arg(generalCode).arg(protocolCode));
    }
}

void CASESession::timeout(void)
{
    if (m_state != State::Established)
    {
        m_state = State::Failed;
        logWarning << "CASE: session timeout";
        emit failed("CASE timeout");
    }
}
