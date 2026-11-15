// NOT REWIEWED

#include <QtEndian>
#include "logger.h"
#include "message.h"
#include "pase.h"
#include "tlv.h"

static const quint8 pointM[] = {0x02, 0x88, 0x6E, 0x2F, 0x97, 0xAC, 0xE4, 0x6E, 0x55, 0xBA, 0x9D, 0xD7, 0x24, 0x25, 0x79, 0xF2, 0x99, 0x3B, 0x64, 0xE1, 0x6E, 0xF3, 0xDC, 0xAB, 0x95, 0xAF, 0xD4, 0x97, 0x33, 0x3D, 0x8F, 0xA1, 0x2F};
static const quint8 pointN[] = {0x03, 0xD8, 0xBB, 0xD6, 0xC6, 0x39, 0xC6, 0x29, 0x37, 0xB0, 0x4D, 0x99, 0x7F, 0x38, 0xC3, 0x77, 0x07, 0x19, 0xC6, 0x29, 0xD7, 0x01, 0x4D, 0x49, 0xA2, 0x4B, 0x4F, 0x98, 0xBA, 0xA1, 0x29, 0x2B, 0x49};

static void passcodeKeys(quint32 passcode, const QByteArray &salt, quint32 iterations, BigNum &w0, BigNum &w1)
{
    BigNum order = BigNum::order();
    QByteArray data;

    passcode = qToLittleEndian(passcode);
    data = Crypto::pbkdf2(QByteArray(reinterpret_cast <char*> (&passcode), sizeof(passcode)), salt, iterations, 80);

    w0 = BigNum::mod(BigNum(data.left(40)), order);
    w1 = BigNum::mod(BigNum(data.mid(40, 40)), order);
}

static QByteArray transcriptItem(const QByteArray &data)
{
    quint64 length = qToLittleEndian <quint64> (data.length());
    return QByteArray(reinterpret_cast <char*> (&length), sizeof(length)).append(data);
}

PASESession::PASESession(QObject *parent) : QObject(parent), m_timer(new QTimer(this)), m_state(State::Idle), m_passcode(0), m_peerMessageCounter(0), m_localSessionId(0), m_peerSessionId(0)
{
    connect(m_timer, &QTimer::timeout, this, &PASESession::timeout);
    m_timer->setSingleShot(true);

    EC_POINT_oct2point(ECPoint::group(), m_m.point(), pointM, sizeof(pointM), nullptr);
    EC_POINT_oct2point(ECPoint::group(), m_n.point(), pointN, sizeof(pointN), nullptr);
}

QByteArray PASESession::verifier(quint32 passcode, const QByteArray &salt, quint32 iterations)
{
    BigNum w0, w1;
    passcodeKeys(passcode, salt, iterations, w0, w1);
    return w0.toData(32).append(ECPoint::multiply(ECPoint::generator(), w1.bn()).toData());
}

void PASESession::start(quint32 passcode, quint16 localSessionId)
{
    MatterTLV::Encoder encoder;

    m_passcode = passcode;
    m_localSessionId = localSessionId;
    m_initiatorRandom = Crypto::randomData(32);
    m_state = State::WaitingPBKDFResponse;
    m_timer->start(PASE_TIMEOUT);

    encoder.openStructure();
    encoder.encodeByteString(1, m_initiatorRandom);
    encoder.encodeUnsignedInt(2, m_localSessionId);
    encoder.encodeUnsignedInt(3, 0);  // passcode id
    encoder.encodeBool(4, false);     // has PBKDF parameters
    encoder.closeContainer();

    m_pbkdfRequest = encoder.data();

    logInfo << "PASE session" << m_localSessionId << "PBKDFParamRequest sent";
    emit sendPBKDFParamRequest(m_pbkdfRequest, m_localSessionId);
}

void PASESession::parsePBKDFParamResponse(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    MatterTLV::Encoder encoder;
    QByteArray random, salt;
    quint32 iterations = 0;

    if (m_state != State::WaitingPBKDFResponse)
    {
        emit failed("Unexpected PBKDFParamResponse");
        return;
    }

    m_pbkdfResponse = payload;

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        switch (item.tag)
        {
            case 1: random = item.value.toByteArray(); break;
            case 3: m_peerSessionId = static_cast <quint16> (item.value.toUInt()); break;

            case 4:
            {
                for (int j = 0; j < item.children.count(); j++)
                {
                    const MatterTLV::Element &parameter = item.children.at(j);

                    switch (parameter.tag)
                    {
                        case 1: iterations = parameter.value.toUInt(); break;
                        case 2: salt = parameter.value.toByteArray(); break;
                    }
                }

                break;
            }
        }
    }

    if (random != m_initiatorRandom)
    {
        fail("Initiator random mismatch");
        return;
    }

    if (!iterations || salt.isEmpty())
    {
        fail("Missing PBKDF parameters");
        return;
    }

    logInfo << "PASE session" << m_localSessionId << "PBKDFParamResponse received, peer session" << m_peerSessionId << "iterations" << iterations << "salt length" << salt.length();
    passcodeKeys(m_passcode, salt, iterations, m_w0, m_w1);

    // pA = x * G + w0 * M
    m_x = BigNum::mod(BigNum(Crypto::randomData(32)), BigNum::order());
    m_pa = ECPoint::add(ECPoint::multiply(ECPoint::generator(), m_x.bn()), ECPoint::multiply(m_m, m_w0.bn()));
    m_state = State::WaitingPake2;

    encoder.openStructure();
    encoder.encodeByteString(1, m_pa.toData());
    encoder.closeContainer();

    logInfo << "PASE session" << m_localSessionId << "Pake1 sent";
    emit sendPake1(encoder.data());
}

void PASESession::parsePake2(const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    MatterTLV::Encoder encoder;
    QByteArray pb, cb, transcript, hash, keys;
    ECPoint point, y, z, v;

    if (m_state != State::WaitingPake2)
    {
        emit failed("Unexpected Pake2");
        return;
    }

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        switch (item.tag)
        {
            case 1: pb = item.value.toByteArray(); break;
            case 2: cb = item.value.toByteArray(); break;
        }
    }

    if (pb.isEmpty() || cb.isEmpty())
    {
        fail("Missing Pake2 data");
        return;
    }

    if (!point.fromData(pb))
    {
        fail("Invalid pB point");
        return;
    }

    // Y = pB - w0 * N, Z = x * Y, V = w1 * Y
    y = ECPoint::subtract(point, ECPoint::multiply(m_n, m_w0.bn()));
    z = ECPoint::multiply(y, m_x.bn());
    v = ECPoint::multiply(y, m_w1.bn());

    transcript.append(transcriptItem(Crypto::sha256(QByteArray(PASE_CONTEXT).append(m_pbkdfRequest).append(m_pbkdfResponse))));
    transcript.append(transcriptItem(QByteArray())); // prover id
    transcript.append(transcriptItem(QByteArray())); // verifier id
    transcript.append(transcriptItem(m_m.toData()));
    transcript.append(transcriptItem(m_n.toData()));
    transcript.append(transcriptItem(m_pa.toData()));
    transcript.append(transcriptItem(point.toData()));
    transcript.append(transcriptItem(z.toData()));
    transcript.append(transcriptItem(v.toData()));
    transcript.append(transcriptItem(m_w0.toData(32)));

    // hash = Ka || Ke, keys = Kca || Kcb
    hash = Crypto::sha256(transcript);
    keys = Crypto::hkdf(hash.left(16), QByteArray(), "ConfirmationKeys", 32);

    if (Crypto::hmac(keys.mid(16, 16), m_pa.toData()) != cb)
    {
        fail("PASE Pake2 verification failed");
        return;
    }

    encoder.openStructure();
    encoder.encodeByteString(1, Crypto::hmac(keys.left(16), pb));
    encoder.closeContainer();

    keys = Crypto::hkdf(hash.mid(16, 16), QByteArray(), "SessionKeys", 48);

    m_encryptKey = keys.left(16);
    m_decryptKey = keys.mid(16, 16);
    m_attestationChallenge = keys.mid(32, 16);
    m_state = State::WaitingStatusReport;

    logInfo << "PASE session" << m_localSessionId << "Pake2 verified, Pake3 sent";
    emit sendPake3(encoder.data());
}

void PASESession::parseStatusReport(const QByteArray &payload)
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

    logInfo << "PASE session" << m_localSessionId << "StatusReport received, general code" << report.generalCode << "protocol" << report.protocolId << "code" << report.protocolCode << "state" << static_cast <int> (m_state);

    if (report.generalCode || report.protocolCode || m_state != State::WaitingStatusReport)
    {
        logWarning << "PASE session" << m_localSessionId << "failed with general code" << report.generalCode << "and protocol code" << report.protocolCode;
        fail(QString("StatusReport error: general=%1 protocol=%2").arg(report.generalCode).arg(report.protocolCode));
        return;
    }

    m_state = State::Established;
    m_timer->stop();

    logInfo << "PASE session" << m_localSessionId << "established with peer session" << m_peerSessionId;
    emit established(m_localSessionId, m_peerSessionId);
}

void PASESession::fail(const QString &reason)
{
    m_state = State::Failed;
    emit failed(reason);
}

void PASESession::timeout(void)
{
    if (m_state == State::Established)
        return;

    logWarning << "PASE session" << m_localSessionId << "timed out";
    fail("PASE timeout");
}
