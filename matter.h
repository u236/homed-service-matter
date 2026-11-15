// NOT REWIEWED

#ifndef MATTER_H
#define MATTER_H

#define SEARCH_TIMEOUT                  60000
#define PING_INTERVAL                   10000
#define PING_TIMEOUT                    60
#define RECONNECT_DELAY                 10000
#define RECONNECT_JITTER                5000
#define THREAD_DATASET_INTERVAL         5000
#define THREAD_DATASET_TIMEOUT          6000
#define COMMISSIONING_DELAY             5000
#define TIMED_REQUEST_TIMEOUT           5000
#define FAIL_SAFE_TIMEOUT               900

#define SUBSCRIPTION_MAX_INTERVAL       60
#define SUBSCRIPTION_TIMEOUT_MARGIN     30
#define SESSION_COUNTER_MARGIN          10000

#define SHARE_ITERATIONS                1000
#define SHARE_TIMEOUT_MIN               180
#define SHARE_TIMEOUT_MAX               900

#define ADMIN_VENDOR_ID                 0xFFF1

#include <QMetaEnum>
#include "ble.h"
#include "case.h"
#include "device.h"
#include "interaction.h"
#include "mdns.h"
#include "message.h"
#include "mrp.h"
#include "pase.h"

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
    AddNOC
};

struct PendingCommission
{
    PASESession        *pase;
    DeviceObject       *device;
    CommissioningState  state;
    MatterService       service;
    QHostAddress        address;
    quint16             port;
    quint16             exchangeId;
    quint16             localSessionId;
    quint32             passcode;
    quint64             nodeId;
    QByteArray          publicKey;
    QByteArray          rcac;
    QByteArray          noc;
    quint32             networkFeatures;
    bool                thread;

    PendingCommission(void) : pase(nullptr), device(nullptr), state(CommissioningState::Idle), port(0), exchangeId(0), localSessionId(0), passcode(0), nodeId(0), networkFeatures(0), thread(false) {}
};

struct PendingCase
{
    CASESession        *session;
    DeviceObject       *device;
    QHostAddress        address;
    quint16             port;
    quint16             exchangeId;
    bool                commissioning;

    PendingCase(void) : session(nullptr), device(nullptr), port(0), exchangeId(0), commissioning(false) {}
};

struct PendingShare
{
    DeviceObject       *device;
    quint16             exchangeId;
    quint32             passcode;
    quint16             discriminator;
    quint16             timeout;
    QByteArray          verifier;
    QByteArray          salt;
    bool                timedRequest;

    PendingShare(void) : device(nullptr), exchangeId(0), passcode(0), discriminator(0), timeout(0), timedRequest(false) {}
};

class Matter : public QObject
{
    Q_OBJECT

public:

    Matter(QSettings *config, QObject *parent);
    ~Matter(void);

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

    inline DeviceList *devices(void) { return m_devices; }
    inline const char *eventName(Event event) { return m_events.valueToKey(static_cast <int> (event)); }

    void connectDevice(const QString &code);
    void connectDevice(DeviceObject *device);
    void discoverDevice(const QString &deviceName);
    void shareDevice(const QString &deviceName, quint16 timeout);
    void updateDevice(const QString &deviceName, const QString &name, const QString &note, bool active, bool discovery, bool cloud);
    void removeDevice(const QString &deviceName);
    void getProperties(const QString &deviceName);
    void deviceAction(const QString &deviceName, quint8 endpointId, const QString &name, const QVariant &value);

    Q_ENUM(Event)

private:

    QTimer *m_searchTimer, *m_reconnectTimer, *m_pingTimer, *m_threadTimer;
    QUdpSocket *m_socket;

    MRP *m_mrp;
    MDNS *m_mdns;
    BLE *m_ble;
    BTP *m_btp;

    SessionManager *m_sessions;
    DeviceList *m_devices;

    QMetaEnum m_events;
    bool m_debug;

    QString m_wifiSsid, m_wifiPassword, m_otbrUrl;
    QByteArray m_threadDataset, m_threadExtendedPanId;
    bool m_threadReady;

    quint64 m_fabricId, m_nodeId, m_rootCaId;
    QByteArray m_fabricKey, m_fabricPublicKey, m_operationalKey, m_operationalPublicKey, m_ipk, m_controllerNoc, m_controllerRcac;

    quint32 m_messageCounter;
    quint16 m_exchangeCounter, m_sessionCounter;

    bool m_searching, m_shortDiscriminator, m_bleCommissioning, m_commissioning;
    quint32 m_passcode;
    quint16 m_discriminator;
    quint64 m_searchNodeId;

    DeviceObject *m_commissionDevice, *m_removeDevice;

    QMap <quint16, PendingCommission> m_pendingCommissions;
    QMap <quint16, PendingCase> m_pendingCases;
    QMap <quint64, PendingShare> m_pendingShares;

    void setFabricCredentials(const QByteArray &fabricKey, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNoc, const QByteArray &controllerRcac, quint64 rootCaId);
    QByteArray generateCertificate(quint64 nodeId, const QByteArray &publicKey, bool root);

    bool fetchThreadDataset(void);
    void resumeThreadDevices(void);

    void searchDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator, quint64 nodeId);
    void discoverDevice(DeviceObject *device);
    void removeDevice(DeviceObject *device);
    void releaseDevice(DeviceObject *device, bool success);
    void shareDevice(DeviceObject *device, quint16 timeout);
    void deviceCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value);

    bool subscribeDevice(DeviceObject *device, SessionInfo *session);
    QList <AttributePath> subscriptionAttributes(DeviceObject *device);
    QList <EventPath> subscriptionEvents(DeviceObject *device);

    void deviceUnreachable(DeviceObject *device);
    void retryConnection(DeviceObject *device);
    void scheduleReconnect(void);

    bool caseInProgress(DeviceObject *device);
    PendingCase *pendingCase(CASESession *session);
    PASESession *createPase(void);

    void startCommissioning(const MatterService &service);
    void continueCommissioning(PendingCommission &commission);
    bool commissioningResponse(PendingCommission &commission, const CommandResponse &response);
    void finishCommissioning(DeviceObject *device);

    void parseSecureChannel(const MatterProtocol::MessageHeader &messageHeader, const MatterProtocol::ProtocolHeader &protocolHeader, const QByteArray &payload);
    void parseInteractionModel(const MatterProtocol::MessageHeader &messageHeader, const MatterProtocol::ProtocolHeader &protocolHeader, const QByteArray &payload);

    void parseReportData(const MatterProtocol::MessageHeader &messageHeader, const MatterProtocol::ProtocolHeader &protocolHeader, const QByteArray &payload);
    bool parseDiscovery(DeviceObject *device, SessionInfo *session, const QList <AttributeReport> &reports);
    void parseStatusResponse(const MatterProtocol::MessageHeader &messageHeader, const QByteArray &payload);
    void parseSubscribeResponse(const MatterProtocol::MessageHeader &messageHeader, const QByteArray &payload);
    void parseInvokeResponse(const MatterProtocol::MessageHeader &messageHeader, const QByteArray &payload);

    MatterProtocol::ProtocolHeader protocolHeader(quint8 opcode, quint16 protocolId, quint16 exchangeId, bool initiator, bool reliable, quint32 ackCounter = 0);
    QByteArray encryptMessage(SessionInfo *session, const MatterProtocol::ProtocolHeader &protocolHeader, const QByteArray &payload, quint64 sourceNodeId);
    QByteArray unencryptedMessage(const MatterProtocol::ProtocolHeader &protocolHeader, const QByteArray &payload);

    void sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, quint32 ackCounter = 0);
    void sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator, quint32 ackCounter = 0);
    void sendRequest(SessionInfo *session, MatterProtocol::InteractionModelOpcode opcode, const QByteArray &payload);
    void sendCommissioningRequest(SessionInfo *session, MatterProtocol::InteractionModelOpcode opcode, const QByteArray &payload, quint16 exchangeId, bool ble);
    void sendSecureChannel(const PendingCommission &commission, MatterProtocol::SecureChannelOpcode opcode, const QByteArray &payload, quint32 ackCounter = 0);

private slots:

    void readyRead(void);
    void searchTimeout(void);
    void reconnectTimeout(void);
    void pingTimeout(void);
    void threadTimeout(void);

    void retransmit(const QByteArray &data, const QHostAddress &address, quint16 port);
    void retransmitFailed(quint32 messageCounter, quint16 exchangeId, const QHostAddress &address, quint16 port);
    void sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator);

    void serviceFound(const MatterService &service);

    void bleDeviceFound(const BLEDevice &device);
    void bleConnected(void);
    void bleDisconnected(void);
    void bleDataReceived(const QByteArray &data);

    void btpHandshakeFinished(void);
    void btpMessageReceived(const QByteArray &message);
    void btpWriteData(const QByteArray &data);

    void caseSendSigma1(const QByteArray &payload);
    void caseSendSigma3(const QByteArray &payload);
    void caseEstablished(quint16 localSessionId, quint16 peerSessionId);
    void caseFailed(const QString &reason);

    void paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId);
    void paseSendPake1(const QByteArray &payload);
    void paseSendPake3(const QByteArray &payload);
    void paseEstablished(quint16 localSessionId, quint16 peerSessionId);
    void paseFailed(const QString &reason);

signals:

    void availabilityUpdated(DeviceObject *device);
    void deviceEvent(DeviceObject *device, Matter::Event event, const QJsonObject &json = QJsonObject());
    void deviceShared(DeviceObject *device, const QString &manualCode, const QString &qrCode, quint16 timeout);
    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

};

#endif
