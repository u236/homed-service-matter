// NOT REWIEWED

#include <QtEndian>
#include "pase.h"
#include "logger.h"
#include "tlv.h"

/*
    SPAKE2+ M and N points for P-256 (RFC 9383):

    M = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
    N = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
*/

// M and N from RFC 9383, compressed format
static const quint8 s_pointM[] = {
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f
};

static const quint8 s_pointN[] = {
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49
};

static QByteArray lengthPrefixed(const QByteArray &data)
{
    QByteArray result(8, 0);
    quint64 len = qToLittleEndian <quint64> (data.length());
    memcpy(result.data(), &len, 8);
    result.append(data);
    return result;
}

PASESession::PASESession(QObject *parent) : QObject(parent), m_state(State::Idle), m_timer(new QTimer(this)), m_passcode(0), m_localSessionId(0), m_peerSessionId(0), m_lastPeerMessageCounter(0)
{
    connect(m_timer, &QTimer::timeout, this, &PASESession::timeout);
    m_timer->setSingleShot(true);
    initPoints();
}

void PASESession::initPoints(void)
{
    EC_POINT_oct2point(ECPoint::group(), m_M.point(), s_pointM, sizeof(s_pointM), nullptr);
    EC_POINT_oct2point(ECPoint::group(), m_N.point(), s_pointN, sizeof(s_pointN), nullptr);
}

void PASESession::start(quint32 passcode, quint16 localSessionId)
{
    m_passcode = passcode;
    m_localSessionId = localSessionId;
    m_initiatorRandom = Crypto::randomBytes(32);
    m_state = State::WaitingPBKDFResponse;
    m_timer->start(PASE_TIMEOUT);

    MatterTLV::Encoder encoder;
    encoder.openStructure();
    encoder.encodeByteString(1, m_initiatorRandom);
    encoder.encodeUnsignedInt(2, m_localSessionId);
    encoder.encodeUnsignedInt(3, 0); // passcodeId = 0
    encoder.encodeBool(4, false);    // hasPBKDFParameters
    encoder.closeContainer();

    m_pbkdfRequest = encoder.data();

    logInfo << "PASE: sending PBKDFParamRequest, sessionId:" << m_localSessionId;
    emit sendPBKDFParamRequest(m_pbkdfRequest, m_localSessionId);
}

void PASESession::computeW0W1(const QByteArray &salt, quint32 iterations)
{
    // passcode → PBKDF2 → w0s (40 bytes) || w1s (40 bytes)
    QByteArray passcodeBytes(4, 0);
    quint32 le = qToLittleEndian(m_passcode);
    memcpy(passcodeBytes.data(), &le, 4);

    QByteArray derived = Crypto::pbkdf2(passcodeBytes, salt, iterations, 80);

    BigNum w0s(derived.left(40));
    BigNum w1s(derived.mid(40, 40));
    BigNum order = BigNum::fromOrder();

    m_w0 = BigNum::mod(w0s, order);
    m_w1 = BigNum::mod(w1s, order);
}

void PASESession::handlePBKDFParamResponse(const QByteArray &payload)
{
    if (m_state != State::WaitingPBKDFResponse)
    {
        emit failed("Unexpected PBKDFParamResponse");
        return;
    }

    m_pbkdfResponse = payload;

    MatterTLV::Decoder decoder(payload);
    MatterTLV::Element root = decoder.decode();

    QByteArray echoedRandom;
    QByteArray salt;
    quint32 iterations = 0;

    for (const MatterTLV::Element &el : root.children)
    {
        switch (el.tag)
        {
            case 1: echoedRandom = el.value.toByteArray(); break;
            case 2: m_peerRandom = el.value.toByteArray(); break;
            case 3: m_peerSessionId = el.value.toUInt(); break;
            case 4: // pbkdf_parameters structure
                for (const MatterTLV::Element &param : el.children)
                {
                    switch (param.tag)
                    {
                        case 1: iterations = param.value.toUInt(); break;
                        case 2: salt = param.value.toByteArray(); break;
                    }
                }
                break;
        }
    }

    logInfo << "PASE: echoed random:" << echoedRandom.toHex() << "ours:" << m_initiatorRandom.toHex() << "peer session:" << m_peerSessionId << "iterations:" << iterations << "salt len:" << salt.length();

    if (echoedRandom != m_initiatorRandom)
    {
        m_state = State::Failed;
        emit failed("Initiator random mismatch");
        return;
    }

    if (!iterations || salt.isEmpty())
    {
        m_state = State::Failed;
        emit failed("Missing PBKDF parameters");
        return;
    }

    logInfo << "PASE: PBKDF params received, iterations:" << iterations << "salt length:" << salt.length();

    computeW0W1(salt, iterations);

    // SPAKE2+ initiator: pA = x*G + w0*M
    QByteArray xBytes = Crypto::randomBytes(32);
    m_x = BigNum(xBytes);

    BigNum order = BigNum::fromOrder();
    m_x = BigNum::mod(m_x, order);

    ECPoint G = ECPoint::generator();
    ECPoint xG = ECPoint::fromMultiply(G, m_x.bn());
    ECPoint w0M = ECPoint::fromMultiply(m_M, m_w0.bn());
    m_pA = ECPoint::add(xG, w0M);

    m_state = State::WaitingPake2;

    MatterTLV::Encoder encoder;
    encoder.openStructure();
    encoder.encodeByteString(1, m_pA.toUncompressed());
    encoder.closeContainer();

    logInfo << "PASE: sending Pake1";
    emit sendPake1(encoder.data());
}

void PASESession::handlePake2(const QByteArray &payload)
{
    if (m_state != State::WaitingPake2)
    {
        emit failed("Unexpected Pake2");
        return;
    }

    MatterTLV::Decoder decoder(payload);
    MatterTLV::Element root = decoder.decode();

    QByteArray pBBytes, cBBytes;

    for (const MatterTLV::Element &el : root.children)
    {
        switch (el.tag)
        {
            case 1: pBBytes = el.value.toByteArray(); break;
            case 2: cBBytes = el.value.toByteArray(); break;
        }
    }

    if (pBBytes.isEmpty() || cBBytes.isEmpty())
    {
        m_state = State::Failed;
        emit failed("Missing Pake2 data");
        return;
    }

    ECPoint pB;

    if (!pB.setFromUncompressed(pBBytes))
    {
        m_state = State::Failed;
        emit failed("Invalid pB point");
        return;
    }

    // initiator: Y = pB - w0*N
    ECPoint w0N = ECPoint::fromMultiply(m_N, m_w0.bn());
    ECPoint Y = ECPoint::subtract(pB, w0N);

    // Z = x * Y (cofactor h=1 for P-256)
    ECPoint Z = ECPoint::fromMultiply(Y, m_x.bn());

    // V = w1 * Y
    ECPoint V = ECPoint::fromMultiply(Y, m_w1.bn());

    // compute transcript
    QByteArray transcript = computeTranscript(m_pA, pB, Z, V);
    QByteArray Kae = Crypto::sha256(transcript);

    // Ka = first 16 bytes, Ke = last 16 bytes
    QByteArray Ka = Kae.left(16);
    QByteArray Ke = Kae.mid(16, 16);

    // derive confirmation keys: Kca || Kcb = HKDF(Ka, nil, "ConfirmationKeys", 32)
    QByteArray Kcab = Crypto::hkdfSha256(Ka, QByteArray(), QByteArray("ConfirmationKeys"), 32);
    QByteArray Kca = Kcab.left(16);
    QByteArray Kcb = Kcab.mid(16, 16);

    // verify cB = HMAC(Kcb, pA) — CHIP convention
    QByteArray pABytes = m_pA.toUncompressed();
    QByteArray expectedCB = Crypto::hmacSha256(Kcb, pABytes);

    if (expectedCB != cBBytes)
    {
        m_state = State::Failed;
        emit failed("PASE Pake2 verification failed");
        return;
    }

    logInfo << "PASE: Pake2 verified, sending Pake3";

    // cA = HMAC(Kca, pB) — CHIP convention
    QByteArray cA = Crypto::hmacSha256(Kca, pBBytes);

    // derive session keys from Ke
    deriveSessionKeys(Ke);

    m_state = State::WaitingStatusReport;

    MatterTLV::Encoder encoder;
    encoder.openStructure();
    encoder.encodeByteString(1, cA);
    encoder.closeContainer();

    emit sendPake3(encoder.data());
}

void PASESession::handleStatusReport(const QByteArray &payload)
{

    // StatusReport: GeneralCode (2 bytes) + ProtocolId (4 bytes) + ProtocolCode (2 bytes)
    if (payload.length() < 8)
    {
        m_state = State::Failed;
        emit failed("Invalid StatusReport");
        return;
    }

    quint16 generalCode = qFromLittleEndian <quint16> (payload.constData());
    quint32 protocolId = qFromLittleEndian <quint32> (payload.constData() + 2);
    quint16 protocolCode = qFromLittleEndian <quint16> (payload.constData() + 6);

    logInfo << "PASE: StatusReport general:" << generalCode << "protocolId:" << protocolId << "protocolCode:" << protocolCode << "state:" << static_cast <int> (m_state);

    if (generalCode == 0 && protocolCode == 0 && m_state == State::WaitingStatusReport)
    {
        m_state = State::Established;
        m_timer->stop();
        logInfo << "PASE: session established, local:" << m_localSessionId << "peer:" << m_peerSessionId;
        emit established(m_localSessionId, m_peerSessionId);
    }
    else
    {
        m_state = State::Failed;
        logWarning << "PASE: failed with general code:" << generalCode << "protocol code:" << protocolCode;
        emit failed(QString("StatusReport error: general=%1 protocol=%2").arg(generalCode).arg(protocolCode));
    }
}

QByteArray PASESession::computeTranscript(const ECPoint &pA, const ECPoint &pB, const ECPoint &Z, const ECPoint &V)
{
    // context = SHA256("CHIP PAKE V1 Commissioning" || PBKDFParamRequest_TLV || PBKDFParamResponse_TLV)
    QByteArray contextInput(PASE_CONTEXT);
    contextInput.append(m_pbkdfRequest);
    contextInput.append(m_pbkdfResponse);
    QByteArray contextHash = Crypto::sha256(contextInput);

    QByteArray tt;

    tt.append(lengthPrefixed(contextHash));
    tt.append(lengthPrefixed(QByteArray()));             // idProver (empty)
    tt.append(lengthPrefixed(QByteArray()));             // idVerifier (empty)
    tt.append(lengthPrefixed(m_M.toUncompressed()));
    tt.append(lengthPrefixed(m_N.toUncompressed()));
    tt.append(lengthPrefixed(pA.toUncompressed()));
    tt.append(lengthPrefixed(pB.toUncompressed()));
    tt.append(lengthPrefixed(Z.toUncompressed()));
    tt.append(lengthPrefixed(V.toUncompressed()));
    tt.append(lengthPrefixed(m_w0.toByteArray(32)));

    return tt;
}

void PASESession::deriveSessionKeys(const QByteArray &ke)
{
    // SEKeys = HKDF(Ke, nil, "SessionKeys", 48)
    // I2RKey (16 bytes) || R2IKey (16 bytes) || AttestationChallenge (16 bytes)
    QByteArray sessionKeys = Crypto::hkdfSha256(ke, QByteArray(), QByteArray("SessionKeys"), 48);

    m_encryptKey = sessionKeys.left(16);
    m_decryptKey = sessionKeys.mid(16, 16);
    m_attestationChallenge = sessionKeys.mid(32, 16);
}

void PASESession::timeout(void)
{
    if (m_state != State::Established)
    {
        m_state = State::Failed;
        logWarning << "PASE: session timeout";
        emit failed("PASE timeout");
    }
}
