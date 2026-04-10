#ifndef CONTROLLER_H
#define CONTROLLER_H

#define SERVICE_VERSION             "0.0.6"
#define UPDATE_PROPERTIES_DELAY     1000

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
        shareDevice,
        updateDevice,
        removeDevice,
        getProperties,
        discoverDevice
    };

    Controller(const QString &configFile);

    Q_ENUM(Command)

private:

    QTimer *m_timer;
    Matter *m_matter;

    QMetaEnum m_commands;
    QString m_haPrefix, m_haStatus;
    bool m_haEnabled, m_haUpdate;

    void publishExposes(DeviceObject *device, bool remove = false);
    void publishProperties(const Device &device);

private slots:

    void mqttConnected(void) override;
    void mqttReceived(const QByteArray &message, const QMqttTopicName &topic) override;

    void updateAvailability(DeviceObject *device);
    void updateProperties(void);

    void deviceUpdated(DeviceObject *device);
    void endpointUpdated(DeviceObject *device, quint8 endpointId);

    void deviceEvent(DeviceObject *device, Matter::Event event, const QJsonObject &json);
    void deviceShared(DeviceObject *device, const QString &manualCode, const QString &qrCode, quint16 timeout);

    void statusUpdated(const QJsonObject &json);

};

#endif
