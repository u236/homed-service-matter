#ifndef CONTROLLER_H
#define CONTROLLER_H

#define SERVICE_VERSION             "0.0.5"
#define UPDATE_PROPERTIES_DELAY     1000

#include <QMetaEnum>
#include "homed.h"
#include "device.h"
#include "matter.h"

class Controller : public HOMEd
{
    Q_OBJECT

public:

    enum class Command
    {
        restartService,
        updateDevice,
        removeDevice,
        getProperties,
        connectDevice,
        shareDevice
    };

    enum class Event
    {
        deviceFound,
        deviceConnecting,
        networkSetup,
        deviceNotFound,
        connectFailed,
        nameDuplicate,
        aboutToRename,
        added,
        updated,
        removed
    };

    Controller(const QString &configFile);

    Q_ENUM(Command)
    Q_ENUM(Event)

private:

    QTimer *m_timer;
    DeviceList *m_devices;
    Matter *m_matter;

    QMetaEnum m_commands, m_events;
    QString m_haPrefix, m_haStatus;
    bool m_haEnabled, m_haUpdate;

    void publishExposes(DeviceObject *device, bool remove = false);
    void publishProperties(const Device &device);
    void publishEvent(const QString &name, Event event);
    void deviceEvent(DeviceObject *device, Event event);

private slots:

    void mqttConnected(void) override;
    void mqttReceived(const QByteArray &message, const QMqttTopicName &topic) override;

    void updateAvailability(DeviceObject *device);
    void updateProperties(void);

    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

    void statusUpdated(const QJsonObject &json);

    void commissioningEvent(const QString &reason, quint64 nodeId);
    void deviceCommissioned(DeviceObject *device);
    void deviceOnline(DeviceObject *device);
    void deviceOffline(DeviceObject *device);
    void deviceRemoved(DeviceObject *device, bool success);
    void deviceShared(DeviceObject *device, const QString &manualCode, const QString &qrCode, quint16 timeout);

};

#endif
