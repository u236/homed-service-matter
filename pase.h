// NOT REWIEWED

#ifndef PASE_H
#define PASE_H

#define PASE_CONTEXT                "CHIP PAKE V1 Commissioning"
#define PASE_TIMEOUT                30000

#include <QTimer>
#include "crypto.h"

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

    inline quint16 localSessionId(void) { return m_localSessionId; }
    inline quint16 peerSessionId(void) { return m_peerSessionId; }

    inline quint32 peerMessageCounter(void) { return m_peerMessageCounter; }
    inline void setPeerMessageCounter(quint32 value) { m_peerMessageCounter = value; }

    inline QByteArray encryptKey(void) { return m_encryptKey; }
    inline QByteArray decryptKey(void) { return m_decryptKey; }
    inline QByteArray attestationChallenge(void) { return m_attestationChallenge; }

    static QByteArray verifier(quint32 passcode, const QByteArray &salt, quint32 iterations);

    void start(quint32 passcode, quint16 localSessionId);

    void parsePBKDFParamResponse(const QByteArray &payload);
    void parsePake2(const QByteArray &payload);
    void parseStatusReport(const QByteArray &payload);

private:

    QTimer *m_timer;
    State m_state;

    quint32 m_passcode, m_peerMessageCounter;
    quint16 m_localSessionId, m_peerSessionId;

    QByteArray m_initiatorRandom, m_pbkdfRequest, m_pbkdfResponse;
    QByteArray m_encryptKey, m_decryptKey, m_attestationChallenge;

    BigNum m_w0, m_w1, m_x;
    ECPoint m_m, m_n, m_pa;

    void fail(const QString &reason);

private slots:

    void timeout(void);

signals:

    void sendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId);
    void sendPake1(const QByteArray &payload);
    void sendPake3(const QByteArray &payload);
    void established(quint16 localSessionId, quint16 peerSessionId);
    void failed(const QString &reason);

};

#endif
