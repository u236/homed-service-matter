#ifndef MATTER_H
#define MATTER_H

#include <QObject>
#include <QUdpSocket>
#include <QTimer>
#include <QMap>
#include "device.h"
#include "message.h"
#include "mrp.h"
#include "mdns.h"
#include "pase.h"
#include "case.h"
#include "session.h"
#include "interaction.h"

class Matter : public QObject
{
    Q_OBJECT

public:

    Matter(QObject *parent);

    void setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk);
    inline QByteArray fabricKey(void) { return m_fabricKey; }
    inline quint64 rootCAId(void) { return m_rootCAId; }
    inline QByteArray ipk(void) { return m_ipk; }

    void addDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator = false);
    void connectDevice(DeviceObject *device);
    void sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value);
    void readAttributes(DeviceObject *device, const QList <AttributePath> &paths);

private:

    enum class CommissioningState
    {
        Idle,
        PASE,
        ArmFailSafe,
        SetRegulatoryConfig,
        ReadBasicInfo,
        RequestPAI,
        RequestDAC,
        RequestAttestation,
        CSRRequest,
        AddTrustedRootCert,
        AddNOC,
        CommissioningComplete,
        Done
    };

    struct PendingCommission
    {
        PASESession *pase;
        QHostAddress address;
        quint16 port;
        quint16 exchangeId;
        quint16 localSessionId;
        quint32 passcode;
        MatterService service;
        CommissioningState state;
        DeviceObject *device;

        quint32 lastPeerCounter;
        bool timedInvokePending;
        QByteArray devicePublicKey;
        QByteArray rcacTLV;
        QByteArray nocTLV;

        PendingCommission(void) : pase(nullptr), port(0), exchangeId(0), localSessionId(0), passcode(0), state(CommissioningState::Idle), device(nullptr), lastPeerCounter(0), timedInvokePending(false) {}
    };

    QUdpSocket *m_udp;
    MRP *m_mrp;
    MDNS *m_mdns;
    SessionManager *m_sessions;
    QTimer *m_searchTimer;

    quint16 m_port;
    bool m_searching;
    bool m_searchShortDiscriminator;
    quint32 m_searchPasscode;
    quint16 m_searchDiscriminator;

    quint32 m_messageCounter;
    quint16 m_exchangeCounter;
    quint16 m_sessionCounter;

    quint64 m_fabricId;
    quint64 m_nodeId;

    QByteArray m_fabricKey;
    QByteArray m_fabricPublicKey;
    QByteArray m_ipk;
    quint64 m_rootCAId;

    QByteArray m_operationalKey;
    QByteArray m_operationalPubKey;
    QByteArray m_controllerNOC;
    QByteArray m_controllerRCAC;

    CASESession *m_pendingCASE;
    quint16 m_caseExchangeId;
    DeviceObject *m_caseDevice;

    QMap <quint16, PendingCommission> m_pendingCommissions;

    void sendRawDatagram(const QByteArray &data, const QHostAddress &address, quint16 port);
    void sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, bool initiator, quint32 ackCounter = 0);
    void sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator, quint32 ackCounter = 0);

    void handleSecureChannel(const MatterProtocol::MessageHeader &msgHeader, const MatterProtocol::ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port);
    void handleInteractionModel(const MatterProtocol::MessageHeader &msgHeader, const MatterProtocol::ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port);

    void sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port);
    void startCommissioning(const MatterService &service);
    void continueCommissioning(PendingCommission &commission);
    QByteArray generateFabricCert(quint64 fabricId, quint64 nodeId, const QByteArray &subjectPubKey, bool isRCAC);

private slots:

    void readyRead(void);
    void searchTimeout(void);

    void mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port);
    void mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId);
    void mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port);

    void mdnsServiceFound(const MatterService &service);

    void caseSendSigma1(const QByteArray &payload, quint16 localSessionId);
    void caseSendSigma3(const QByteArray &payload);
    void caseEstablished(quint16 localSessionId, quint16 peerSessionId);
    void caseFailed(const QString &reason);

    void paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId);
    void paseSendPake1(const QByteArray &payload);
    void paseSendPake3(const QByteArray &payload);
    void paseEstablished(quint16 localSessionId, quint16 peerSessionId);
    void paseFailed(const QString &reason);

public:

    static bool parseQRCode(const QString &payload, quint32 &passcode, quint16 &discriminator);
    static bool parseManualCode(const QString &code, quint32 &passcode, quint16 &discriminator);

signals:

    void deviceCommissioned(DeviceObject *device);

};

#endif
