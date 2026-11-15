// NOT REWIEWED

#ifndef DEVICE_H
#define DEVICE_H

#define MATTER_PORT                 5540
#define STORE_DATABASE_DELAY        20

#include <QHostAddress>
#include "action.h"
#include "case.h"
#include "endpoint.h"
#include "expose.h"
#include "property.h"

class EndpointObject : public AbstractEndpointObject
{

public:

    EndpointObject(quint8 id, const Device &device) :
        AbstractEndpointObject(id, device) {}

    inline QList <quint32> &clusters(void) { return m_clusters; }
    inline QList <Property> &properties(void) { return m_properties; }
    inline QList <Action> &actions(void) { return m_actions; }

private:

    QList <quint32> m_clusters;
    QList <Property> m_properties;
    QList <Action> m_actions;

};

class DeviceObject : public AbstractDeviceObject
{
    Q_OBJECT

public:

    DeviceObject(quint64 nodeId, const QString &name) :
        AbstractDeviceObject(name), m_nodeId(nodeId), m_vendorId(0), m_productId(0), m_fabricIndex(0), m_networkPort(MATTER_PORT), m_thread(false), m_batteryPowered(false), m_subscriptionPrimed(true), m_subscriptionInterval(0), m_reconnectTime(0), m_lastSeen(0),
        m_sessionLocalId(0), m_sessionPeerId(0), m_sessionCounter(0), m_sessionIdleInterval(SESSION_IDLE_INTERVAL), m_sessionActiveInterval(SESSION_ACTIVE_INTERVAL), m_sessionActiveThreshold(SESSION_ACTIVE_THRESHOLD) {}

    inline quint64 nodeId(void) { return m_nodeId; }
    inline QString address(void) { return QString::number(m_nodeId, 16); }

    inline quint16 vendorId(void) { return m_vendorId; }
    inline void setVendorId(quint16 value) { m_vendorId = value; }

    inline quint16 productId(void) { return m_productId; }
    inline void setProductId(quint16 value) { m_productId = value; }

    inline quint8 fabricIndex(void) { return m_fabricIndex; }
    inline void setFabricIndex(quint8 value) { m_fabricIndex = value; }

    inline QHostAddress networkAddress(void) { return m_networkAddress; }
    inline void setNetworkAddress(const QHostAddress &value) { m_networkAddress = value; }

    inline quint16 networkPort(void) { return m_networkPort; }
    inline void setNetworkPort(quint16 value) { m_networkPort = value; }

    inline bool thread(void) { return m_thread; }
    inline void setThread(bool value) { m_thread = value; }

    inline bool batteryPowered(void) { return m_batteryPowered; }
    inline void setBatteryPowered(bool value) { m_batteryPowered = value; }

    inline bool subscriptionPrimed(void) { return m_subscriptionPrimed; }
    inline void setSubscriptionPrimed(bool value) { m_subscriptionPrimed = value; }

    inline quint16 subscriptionInterval(void) { return m_subscriptionInterval; }
    inline void setSubscriptionInterval(quint16 value) { m_subscriptionInterval = value; }

    inline qint64 reconnectTime(void) { return m_reconnectTime; }
    inline void setReconnectTime(qint64 value) { m_reconnectTime = value; }

    inline qint64 lastSeen(void) { return m_lastSeen; }
    inline void setLastSeen(qint64 value) { m_lastSeen = value; }
    inline void updateLastSeen(void) { m_lastSeen = QDateTime::currentSecsSinceEpoch(); }

    inline QByteArray resumptionId(void) { return m_resumptionId; }
    inline QByteArray resumptionSecret(void) { return m_resumptionSecret; }
    inline void setResumption(const QByteArray &id, const QByteArray &secret) { m_resumptionId = id; m_resumptionSecret = secret; }

    inline quint16 sessionLocalId(void) { return m_sessionLocalId; }
    inline quint16 sessionPeerId(void) { return m_sessionPeerId; }

    inline QByteArray sessionEncryptKey(void) { return m_sessionEncryptKey; }
    inline QByteArray sessionDecryptKey(void) { return m_sessionDecryptKey; }
    inline QByteArray sessionAttestation(void) { return m_sessionAttestation; }

    inline quint32 sessionCounter(void) { return m_sessionCounter; }
    inline void setSessionCounter(quint32 value) { m_sessionCounter = value; }

    inline quint32 sessionIdleInterval(void) { return m_sessionIdleInterval; }
    inline quint32 sessionActiveInterval(void) { return m_sessionActiveInterval; }
    inline quint16 sessionActiveThreshold(void) { return m_sessionActiveThreshold; }

    inline bool sessionStored(void) { return m_sessionLocalId && !m_sessionEncryptKey.isEmpty() && !m_sessionDecryptKey.isEmpty(); }

    void storeSession(SessionInfo *session);
    void restoreSession(SessionInfo &session);
    void parseSession(const QJsonObject &json);
    QJsonObject serializeSession(void);

    void updateEndpoint(quint8 endpointId);

private:

    quint64 m_nodeId;
    quint16 m_vendorId, m_productId;
    quint8 m_fabricIndex;

    QHostAddress m_networkAddress;
    quint16 m_networkPort;
    bool m_thread, m_batteryPowered, m_subscriptionPrimed;

    quint16 m_subscriptionInterval;
    qint64 m_reconnectTime, m_lastSeen;

    QByteArray m_resumptionId, m_resumptionSecret;

    quint16 m_sessionLocalId, m_sessionPeerId;
    QByteArray m_sessionEncryptKey, m_sessionDecryptKey, m_sessionAttestation;
    quint32 m_sessionCounter, m_sessionIdleInterval, m_sessionActiveInterval;
    quint16 m_sessionActiveThreshold;

signals:

    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

};

class DeviceList : public QObject, public QList <Device>
{
    Q_OBJECT

public:

    DeviceList(QSettings *config, QObject *parent);
    ~DeviceList(void);

    inline bool names(void) { return m_names; }

    inline QByteArray fabricKey(void) { return m_fabricKey; }
    inline QByteArray ipk(void) { return m_ipk; }
    inline QByteArray operationalKey(void) { return m_operationalKey; }
    inline QByteArray controllerNoc(void) { return m_controllerNoc; }
    inline QByteArray controllerRcac(void) { return m_controllerRcac; }
    inline quint64 rootCaId(void) { return m_rootCaId; }

    void init(void);
    void storeDatabase(bool sync = false);
    void setFabricCredentials(const QByteArray &fabricKey, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNoc, const QByteArray &controllerRcac, quint64 rootCaId);

    quint64 generateNodeId(void);

    Device byName(const QString &name, int *index = nullptr);
    Device byNodeId(quint64 nodeId);
    Device parse(const QJsonObject &json);

    void addEndpoint(DeviceObject *device, quint8 endpointId, const QList <quint32> &clusters);
    void setupEndpoint(DeviceObject *device, quint8 endpointId);
    void updateMultiple(DeviceObject *device);

private:

    QTimer *m_databaseTimer;
    QFile m_databaseFile;
    bool m_names, m_sync;

    QByteArray m_fabricKey, m_ipk, m_operationalKey, m_controllerNoc, m_controllerRcac;
    quint64 m_rootCaId;

    QMap <QString, QVariant> m_exposeOptions;

    void unserializeDevices(const QJsonArray &devices);
    QJsonArray serializeDevices(void);

private slots:

    void writeDatabase(void);

};

inline QDebug operator << (QDebug debug, DeviceObject *device) { return debug << "device" << device->name(); }
inline QDebug operator << (QDebug debug, const Device &device) { return debug << "device" << device->name(); }

#endif
