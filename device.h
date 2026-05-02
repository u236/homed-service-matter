// NOT REWIEWED

#ifndef DEVICE_H
#define DEVICE_H

#define DEFAULT_ENDPOINT        1
#define STORE_DATABASE_DELAY    20

#include <QMetaEnum>
#include <QHostAddress>
#include "action.h"
#include "endpoint.h"
#include "property.h"

class EndpointObject : public AbstractEndpointObject
{

public:

    EndpointObject(quint8 id, const Device &device) : AbstractEndpointObject(id, device) {}

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
        AbstractDeviceObject(name), m_nodeId(nodeId), m_fabricIndex(0), m_vendorId(0), m_productId(0), m_networkPort(5540), m_subMaxInterval(0), m_nextReconnectAt(0), m_thread(false), m_batteryPowered(false), m_subscriptionPrimed(true), m_lastSeen(0),
        m_sessionLocalId(0), m_sessionPeerId(0), m_sessionLocalCounter(0), m_sessionIdleInterval(500), m_sessionActiveInterval(300), m_sessionActiveThreshold(4000) {}

    inline QByteArray resumptionID(void) { return m_resumptionID; }
    inline void setResumptionID(const QByteArray &value) { m_resumptionID = value; }

    inline QByteArray resumptionSharedSecret(void) { return m_resumptionSharedSecret; }
    inline void setResumptionSharedSecret(const QByteArray &value) { m_resumptionSharedSecret = value; }

    inline quint64 nodeId(void) { return m_nodeId; }
    inline void setNodeId(quint64 value) { m_nodeId = value; }

    inline quint8 fabricIndex(void) { return m_fabricIndex; }
    inline void setFabricIndex(quint8 value) { m_fabricIndex = value; }

    inline quint16 vendorId(void) { return m_vendorId; }
    inline void setVendorId(quint16 value) { m_vendorId = value; }

    inline quint16 productId(void) { return m_productId; }
    inline void setProductId(quint16 value) { m_productId = value; }

    inline QHostAddress networkAddress(void) { return m_networkAddress; }
    inline void setNetworkAddress(const QHostAddress &value) { m_networkAddress = value; }

    inline quint16 networkPort(void) { return m_networkPort; }
    inline void setNetworkPort(quint16 value) { m_networkPort = value; }

    inline quint16 subMaxInterval(void) { return m_subMaxInterval; }
    inline void setSubMaxInterval(quint16 value) { m_subMaxInterval = value; }

    inline qint64 nextReconnectAt(void) { return m_nextReconnectAt; }
    inline void setNextReconnectAt(qint64 value) { m_nextReconnectAt = value; }

    inline bool thread(void) { return m_thread; }
    inline void setThread(bool value) { m_thread = value; }

    inline bool batteryPowered(void) { return m_batteryPowered; }
    inline void setBatteryPowered(bool value) { m_batteryPowered = value; }

    inline bool subscriptionPrimed(void) { return m_subscriptionPrimed; }
    inline void setSubscriptionPrimed(bool value) { m_subscriptionPrimed = value; }

    inline qint64 lastSeen(void) { return m_lastSeen; }
    inline void setLastSeen(qint64 value) { m_lastSeen = value; }
    inline void updateLastSeen(void) { m_lastSeen = QDateTime::currentSecsSinceEpoch(); }

    inline quint16 sessionLocalId(void) { return m_sessionLocalId; }
    inline void setSessionLocalId(quint16 value) { m_sessionLocalId = value; }

    inline quint16 sessionPeerId(void) { return m_sessionPeerId; }
    inline void setSessionPeerId(quint16 value) { m_sessionPeerId = value; }

    inline QByteArray sessionI2RKey(void) { return m_sessionI2RKey; }
    inline void setSessionI2RKey(const QByteArray &value) { m_sessionI2RKey = value; }

    inline QByteArray sessionR2IKey(void) { return m_sessionR2IKey; }
    inline void setSessionR2IKey(const QByteArray &value) { m_sessionR2IKey = value; }

    inline QByteArray sessionAttestation(void) { return m_sessionAttestation; }
    inline void setSessionAttestation(const QByteArray &value) { m_sessionAttestation = value; }

    inline quint32 sessionLocalCounter(void) { return m_sessionLocalCounter; }
    inline void setSessionLocalCounter(quint32 value) { m_sessionLocalCounter = value; }

    inline quint32 sessionIdleInterval(void) { return m_sessionIdleInterval; }
    inline void setSessionIdleInterval(quint32 value) { m_sessionIdleInterval = value; }

    inline quint32 sessionActiveInterval(void) { return m_sessionActiveInterval; }
    inline void setSessionActiveInterval(quint32 value) { m_sessionActiveInterval = value; }

    inline quint16 sessionActiveThreshold(void) { return m_sessionActiveThreshold; }
    inline void setSessionActiveThreshold(quint16 value) { m_sessionActiveThreshold = value; }

    inline bool hasPersistedSession(void) { return m_sessionLocalId && !m_sessionI2RKey.isEmpty() && !m_sessionR2IKey.isEmpty(); }

    inline QString address(void) { return QString::number(m_nodeId, 16); }

    void updateEndpoint(quint8 endpointId);

signals:

    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

private:

    quint64 m_nodeId;
    quint8 m_fabricIndex;
    quint16 m_vendorId, m_productId;
    QHostAddress m_networkAddress;
    quint16 m_networkPort;
    quint16 m_subMaxInterval;
    qint64 m_nextReconnectAt;
    bool m_thread;
    bool m_batteryPowered;
    bool m_subscriptionPrimed;
    qint64 m_lastSeen;
    QByteArray m_resumptionID;
    QByteArray m_resumptionSharedSecret;
    quint16 m_sessionLocalId, m_sessionPeerId;
    QByteArray m_sessionI2RKey, m_sessionR2IKey, m_sessionAttestation;
    quint32 m_sessionLocalCounter;
    quint32 m_sessionIdleInterval, m_sessionActiveInterval;
    quint16 m_sessionActiveThreshold;

};

class DeviceList : public QObject, public QList <Device>
{
    Q_OBJECT

public:

    DeviceList(QSettings *config, QObject *parent);
    ~DeviceList(void);

    inline bool names(void) { return m_names; }
    inline QMap <QString, QVariant> &exposeOptions(void) { return m_exposeOptions; }

    void init(void);
    void store(bool sync = false);

    quint64 generateNodeId(void);

    inline QByteArray fabricKey(void) { return m_fabricKey; }
    inline quint64 rootCAId(void) { return m_rootCAId; }
    inline QByteArray ipk(void) { return m_ipk; }
    inline QByteArray operationalKey(void) { return m_operationalKey; }
    inline QByteArray controllerNOC(void) { return m_controllerNOC; }
    inline QByteArray controllerRCAC(void) { return m_controllerRCAC; }

    void setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNOC, const QByteArray &controllerRCAC);

    void addEndpoint(DeviceObject *device, quint8 endpointId, const QList <quint32> &clusters);
    void setupEndpoint(DeviceObject *device, quint8 endpointId);
    void updateMultiple(DeviceObject *device);

    Device byName(const QString &name, int *index = nullptr);
    Device byNodeId(quint64 nodeId);
    Device parse(const QJsonObject &json);

private:

    QTimer *m_timer;
    QFile m_file;
    bool m_names, m_sync;

    QByteArray m_fabricKey;
    quint64 m_rootCAId;
    QByteArray m_ipk;
    QByteArray m_operationalKey;
    QByteArray m_controllerNOC;
    QByteArray m_controllerRCAC;

    QMap <QString, QVariant> m_exposeOptions;

    void unserialize(const QJsonArray &devices);
    QJsonArray serialize(void);

private slots:

    void writeDatabase(void);

};

inline QDebug operator << (QDebug debug, DeviceObject *device) { return debug << "device" << device->name(); }
inline QDebug operator << (QDebug debug, const Device &device) { return debug << "device" << device->name(); }

#endif
