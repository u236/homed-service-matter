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
#include "session.h"
#include "interaction.h"

class Matter : public QObject
{
    Q_OBJECT

public:

    Matter(QObject *parent);

    void setPermitJoin(quint32 duration);
    void setPasscode(quint32 passcode);
    void sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value);
    void readAttributes(DeviceObject *device, const QList <AttributePath> &paths);

private:

    enum class CommissioningState
    {
        Idle,
        PASE,
        ArmFailSafe,
        ReadBasicInfo,
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
        MatterService service;
        CommissioningState state;
        DeviceObject *device;

        PendingCommission(void) : pase(nullptr), port(0), exchangeId(0), localSessionId(0), state(CommissioningState::Idle), device(nullptr) {}
    };

    QUdpSocket *m_udp;
    MRP *m_mrp;
    MDNS *m_mdns;
    SessionManager *m_sessions;
    QTimer *m_permitJoinTimer;

    quint16 m_port;
    bool m_permitJoin;
    quint32 m_passcode;

    quint32 m_messageCounter;
    quint16 m_exchangeCounter;
    quint16 m_sessionCounter;

    quint64 m_fabricId;
    quint64 m_nodeId;

    QMap <quint16, PendingCommission> m_pendingCommissions;

    void sendRawDatagram(const QByteArray &data, const QHostAddress &address, quint16 port);
    void sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, bool initiator, quint32 ackCounter = 0);
    void sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator);

    void handleSecureChannel(const MatterProtocol::MessageHeader &msgHeader, const MatterProtocol::ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port);
    void handleInteractionModel(const MatterProtocol::MessageHeader &msgHeader, const MatterProtocol::ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port);

    void sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port);
    void startCommissioning(const MatterService &service);
    void continueCommissioning(PendingCommission &commission);

private slots:

    void readyRead(void);
    void permitJoinTimeout(void);

    void mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port);
    void mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId);
    void mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port);

    void mdnsServiceFound(const MatterService &service);

    void paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId);
    void paseSendPake1(const QByteArray &payload);
    void paseSendPake3(const QByteArray &payload);
    void paseEstablished(quint16 localSessionId, quint16 peerSessionId);
    void paseFailed(const QString &reason);

signals:

    void deviceCommissioned(DeviceObject *device);

};

#endif
