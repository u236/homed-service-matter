#ifndef CONTROLLER_H
#define CONTROLLER_H

#define SERVICE_VERSION                 "0.1.4"
#define UPDATE_DEVICE_DATA_INTERVAL     5000
#define UPDATE_PROPERTIES_DELAY         1000

#include "homed.h"
#include "matter.h"

class Controller : public HOMEd
{
    Q_OBJECT

public:

    enum class Command
    {
        restartService,
        connectDevice,
        discoverDevice,
        shareDevice,
        updateDevice,
        removeDevice,
        getProperties
    };

    Controller(const QString &configFile);

    Q_ENUM(Command)

private:

    QTimer *m_deviceDataTimer, *m_propertiesTimer;
    Matter *m_matter;

    QMetaEnum m_commands;
    QString m_haPrefix, m_haStatus;
    bool m_haEnabled, m_haUpdate;

    QMap <quint64, qint64> m_lastSeen;

    void publishExposes(DeviceObject *device, bool remove = false);
    void publishProperties(const Device &device);

public slots:

    void quit(void) override;

private slots:

    void mqttConnected(void) override;
    void mqttReceived(const QByteArray &message, const QMqttTopicName &topic) override;

    void updateAvailability(DeviceObject *device);
    void updateDeviceData(void);
    void updateProperties(void);

    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

    void deviceEvent(DeviceObject *device, Matter::Event event, const QJsonObject &json);
    void deviceShared(DeviceObject *device, const QString &manualCode, const QString &qrCode, quint16 timeout);

};

#endif
