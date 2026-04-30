// NOT REWIEWED

#ifndef MATTER_H
#define MATTER_H

#include "device.h"
#include "message.h"
#include "mrp.h"
#include "mdns.h"
#include "pase.h"
#include "case.h"
#include "interaction.h"
#include "ble.h"

class Matter : public QObject
{
    Q_OBJECT

public:

    enum class Event
    {
        deviceFound,
        deviceConnecting,
        networkSetup,
        deviceNotFound,
        connectFailed,
        nameDuplicate,
        aboutToUpdate,
        added,
        updated,
        removed
    };

    Q_ENUM(Event)

    Matter(QSettings *config, QObject *parent);
    ~Matter(void);

    void setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNOC = QByteArray(), const QByteArray &controllerRCAC = QByteArray());

    inline QByteArray fabricKey(void) { return m_fabricKey; }
    inline quint64 rootCAId(void) { return m_rootCAId; }
    inline QByteArray ipk(void) { return m_ipk; }
    inline QByteArray controllerNOC(void) { return m_controllerNOC; }
    inline QByteArray controllerRCAC(void) { return m_controllerRCAC; }

    inline DeviceList *devices(void) { return m_devices; }
    inline const char *eventName(Event event) { return m_events.valueToKey(static_cast <int> (event)); }

    void connectDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator = false, quint64 nodeId = 0);
    void connectDevice(DeviceObject *device);
    void discoverDevice(DeviceObject *device);
    void removeDevice(DeviceObject *device);
    void shareDevice(DeviceObject *device, quint16 timeout = 300);
    void sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value);
    void readAttributes(DeviceObject *device, const QList <AttributePath> &paths);

    void connectDevice(const QString &code);
    void discoverDevice(const QString &deviceName);
    void shareDevice(const QString &deviceName, quint16 timeout);
    void updateDevice(const QString &deviceName, const QString &name, const QString &note, bool active, bool discovery, bool cloud);
    void removeDevice(const QString &deviceName);
    void getProperties(const QString &deviceName);
    void deviceAction(const QString &deviceName, quint8 endpointId, const QString &name, const QVariant &value);

    static QString generateManualCode(quint32 passcode, quint16 discriminator);
    static QString generateQRCode(quint32 passcode, quint16 discriminator);
    static QByteArray extractThreadExtPanId(const QByteArray &dataset);

private:

    enum class CommissioningState
    {
        Idle,
        PASE,
        ReadNetworkType,
        AddWiFiNetwork,
        AddThreadNetwork,
        ConnectNetwork,
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
        quint64 assignedNodeId;
        MatterService service;
        CommissioningState state;
        DeviceObject *device;

        quint32 lastPeerCounter;
        bool timedInvokePending;
        QByteArray devicePublicKey;
        QByteArray rcacTLV;
        QByteArray nocTLV;
        quint32 networkFeatureMap;
        bool useThread;

        PendingCommission(void) : pase(nullptr), port(0), exchangeId(0), localSessionId(0), passcode(0), assignedNodeId(0), state(CommissioningState::Idle), device(nullptr), lastPeerCounter(0), timedInvokePending(false), networkFeatureMap(0), useThread(false) {}
    };

    QUdpSocket *m_udp;
    MRP *m_mrp;
    MDNS *m_mdns;
    BLE *m_ble;
    BTP *m_btp;
    SessionManager *m_sessions;
    QTimer *m_searchTimer;
    QTimer *m_reconnectTimer;
    QTimer *m_pingTimer;

    quint16 m_port;
    bool m_debug;
    bool m_searching;
    bool m_searchShortDiscriminator;
    quint32 m_searchPasscode;
    quint16 m_searchDiscriminator;
    quint64 m_searchNodeId;

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

    struct PendingCASE
    {
        CASESession *session;
        DeviceObject *device;
        quint16 exchangeId;
        QHostAddress address;
        quint16 port;
        bool needsCommissioningComplete;

        PendingCASE(void) : session(nullptr), device(nullptr), exchangeId(0), port(0), needsCommissioningComplete(false) {}
    };

    QMap <quint16, PendingCASE> m_pendingCASEs; // keyed by exchangeId
    bool m_caseNeedsCommissioningComplete;      // set during commissioning, consumed by connectDevice
    DeviceObject *m_pendingCommissionDevice;
    DeviceObject *m_pendingRemoveDevice;

    DeviceList *m_devices;
    QMetaEnum m_events;

    QString m_wifiSSID;
    QString m_wifiPassword;
    QByteArray m_threadDataset;
    QByteArray m_threadExtPanId;
    bool m_bleCommissioning;

    QMap <quint16, PendingCommission> m_pendingCommissions;

    struct PendingShare
    {
        DeviceObject *device;
        quint16 exchangeId;
        quint32 passcode;
        quint16 discriminator;
        quint16 timeout;
        quint32 lastPeerCounter;
        bool timedInvokePending;

        PendingShare(void) : device(nullptr), exchangeId(0), passcode(0), discriminator(0), timeout(0), lastPeerCounter(0), timedInvokePending(false) {}
    };

    QMap <quint64, PendingShare> m_pendingShares; // keyed by nodeId
    QMap <quint64, QByteArray> m_shareVerifiers;
    QMap <quint64, QByteArray> m_shareSalts;
    QMap <quint64, quint32> m_shareIterations;

    void handleDeviceUnreachable(DeviceObject *device);
    void connectDeviceSignals(DeviceObject *device);
    QList <AttributePath> buildSubscribePaths(DeviceObject *device);
    QList <EventPath> buildSubscribeEvents(DeviceObject *device);
    void subscribeDevice(DeviceObject *device, SessionInfo *session);
    void sendBleMessage(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator);
    void sendEncryptedBle(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator);
    void sendCommissioningMessage(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId);
    void sendRawDatagram(const QByteArray &data, const QHostAddress &address, quint16 port);
    void sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, bool initiator, quint32 ackCounter = 0);
    void sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator, quint32 ackCounter = 0);

    void handleSecureChannel(const MatterProtocol::MessageHeader &msgHeader, const MatterProtocol::ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port);
    void handleInteractionModel(const MatterProtocol::MessageHeader &msgHeader, const MatterProtocol::ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port);

    void sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator);
    void startCommissioning(const MatterService &service);
    void continueCommissioning(PendingCommission &commission);
    QByteArray generateFabricCert(quint64 fabricId, quint64 nodeId, const QByteArray &subjectPubKey, bool isRCAC);

    void resetReconnectBackoff(DeviceObject *device);
    void scheduleReconnect(void);
    PendingCASE *findPendingCASE(CASESession *session);

private slots:

    void readyRead(void);
    void searchTimeout(void);
    void reconnectTimeout(void);
    void pingTimeout(void);

    void mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port);
    void mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId, const QHostAddress &address, quint16 port);
    void mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator);

    void mdnsServiceFound(const MatterService &service);

    void bleDeviceFound(const BLEDevice &device);
    void bleConnected(void);
    void bleDisconnected(void);
    void bleDataReceived(const QByteArray &data);
    void btpHandshakeComplete(void);
    void btpMessageReceived(const QByteArray &message);
    void btpWriteData(const QByteArray &data);

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

    void updateAvailability(DeviceObject *device);
    void deviceEvent(DeviceObject *device, Matter::Event event, const QJsonObject &json = QJsonObject());
    void deviceShared(DeviceObject *device, const QString &manualCode, const QString &qrCode, quint16 timeout);
    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

};

#endif
