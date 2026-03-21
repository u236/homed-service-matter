#ifndef PASE_H
#define PASE_H

#include <QObject>
#include <QHostAddress>
#include <QTimer>
#include "crypto.h"
#include "tlv.h"

/*
    PASE — Password Authenticated Session Establishment (Matter spec 4.13)

    Uses SPAKE2+ over P-256 for mutual authentication with a numeric passcode.

    Commissioner (initiator) flow:
    1. Send PBKDFParamRequest  → get salt, iterations
    2. Send Pake1 (pA)        → get Pake2 (pB, cB), verify cB
    3. Send Pake3 (cA)        → session established

    SPAKE2+ points (RFC 9383 / Matter spec):
    M, N are fixed points on P-256 used as generators.
*/

#define PASE_CONTEXT           "CHIP PAKE V1 Commissioning"
#define PASE_DEFAULT_PASSCODE  20202021
#define PASE_DEFAULT_ITERATIONS 100
#define PASE_DEFAULT_SALT_LENGTH 32
#define PASE_TIMEOUT           30000

class PASESession : public QObject
{
    Q_OBJECT

public:

    enum class State
    {
        Idle,
        WaitingPBKDFResponse,
        WaitingPake2,
        WaitingStatusReport,
        Established,
        Failed
    };

    PASESession(QObject *parent);

    void start(quint32 passcode, quint16 localSessionId);
    inline void setLastPeerMessageCounter(quint32 value) { m_lastPeerMessageCounter = value; }
    inline quint32 lastPeerMessageCounter(void) const { return m_lastPeerMessageCounter; }

    void handlePBKDFParamResponse(const QByteArray &payload);
    void handlePake2(const QByteArray &payload);
    void handleStatusReport(const QByteArray &payload);

    inline State state(void) const { return m_state; }
    inline quint16 localSessionId(void) const { return m_localSessionId; }
    inline quint16 peerSessionId(void) const { return m_peerSessionId; }

    inline QByteArray encryptKey(void) const { return m_encryptKey; }
    inline QByteArray decryptKey(void) const { return m_decryptKey; }
    inline QByteArray attestationChallenge(void) const { return m_attestationChallenge; }

private:

    State m_state;
    QTimer *m_timer;

    quint32 m_passcode;
    quint16 m_localSessionId;
    quint16 m_peerSessionId;

    QByteArray m_initiatorRandom;
    QByteArray m_peerRandom;
    QByteArray m_pbkdfRequest;
    QByteArray m_pbkdfResponse;
    quint32 m_lastPeerMessageCounter;

    // SPAKE2+ state
    BigNum m_w0, m_w1;
    BigNum m_x;
    ECPoint m_pA;
    ECPoint m_M, m_N;

    // session keys
    QByteArray m_encryptKey;
    QByteArray m_decryptKey;
    QByteArray m_attestationChallenge;

    void computeW0W1(const QByteArray &salt, quint32 iterations);
    QByteArray computeTranscript(const ECPoint &pA, const ECPoint &pB, const ECPoint &Z, const ECPoint &V);
    void deriveSessionKeys(const QByteArray &ke);

    void initPoints(void);

private slots:

    void timeout(void);

signals:

    void sendPBKDFParamRequest(const QByteArray &tlvPayload, quint16 localSessionId);
    void sendPake1(const QByteArray &tlvPayload);
    void sendPake3(const QByteArray &tlvPayload);
    void established(quint16 localSessionId, quint16 peerSessionId);
    void failed(const QString &reason);

};

#endif
