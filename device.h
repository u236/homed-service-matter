#ifndef DEVICE_H
#define DEVICE_H

#define DEFAULT_ENDPOINT        1
#define STORE_DATABASE_DELAY    20

#include <QMetaEnum>
#include <QHostAddress>
#include "endpoint.h"

class EndpointObject : public AbstractEndpointObject
{

public:

    EndpointObject(quint8 id, const Device &device) : AbstractEndpointObject(id, device) {}

    inline QMap <QString, QVariant> &status(void) { return m_status; }

private:

    QMap <QString, QVariant> m_status;

};

class DeviceObject : public AbstractDeviceObject
{
    Q_OBJECT

public:

    DeviceObject(quint64 nodeId, const QString &name) :
        AbstractDeviceObject(name), m_nodeId(nodeId), m_fabricIndex(0), m_vendorId(0), m_productId(0), m_networkPort(5540) {}

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

    inline QString address(void) { return QString("0x%1").arg(m_nodeId, 16, 16, QLatin1Char('0')); }

    void updateEndpoint(quint8 endpointId, const QString &property, const QVariant &value);

signals:

    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

private:

    quint64 m_nodeId;
    quint8 m_fabricIndex;
    quint16 m_vendorId, m_productId;
    QHostAddress m_networkAddress;
    quint16 m_networkPort;

};

class DeviceList : public QObject, public QList <Device>
{
    Q_OBJECT

public:

    DeviceList(QSettings *config, QObject *parent);
    ~DeviceList(void);

    inline bool names(void) { return m_names; }
    inline void setNames(bool value) { m_names = value; }

    void init(void);
    void store(bool sync = false);

    inline QByteArray fabricKey(void) { return m_fabricKey; }
    inline quint64 rootCAId(void) { return m_rootCAId; }
    inline QByteArray ipk(void) { return m_ipk; }
    inline QByteArray operationalKey(void) { return m_operationalKey; }

    void setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk, const QByteArray &operationalKey);

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

    QMap <QString, QVariant> m_exposeOptions;

    void unserialize(const QJsonArray &devices);
    QJsonArray serialize(void);

private slots:

    void writeDatabase(void);

signals:

    void statusUpdated(const QJsonObject &json);

};

inline QDebug operator << (QDebug debug, DeviceObject *device) { return debug << "device" << device->name(); }
inline QDebug operator << (QDebug debug, const Device &device) { return debug << "device" << device->name(); }

#endif
