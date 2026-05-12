#ifndef ACTION_H
#define ACTION_H

#include <QSharedPointer>
#include <QVariant>
#include "clusters.h"
#include "endpoint.h"

class ActionObject;
typedef QSharedPointer <ActionObject> Action;

class ActionObject : public AbstractMetaObject
{

public:

    ActionObject(const QString &name, quint32 clusterId) : AbstractMetaObject(name), m_clusterId(clusterId) {}

    virtual ~ActionObject(void) {}
    virtual QByteArray request(quint16 endpointId, const QVariant &data) = 0;

    // InteractionModelOpcode the encoded payload should be sent as. defaults to InvokeRequest (0x08) since
    // most actions invoke a command; attribute-write actions override to WriteRequest (0x06)
    virtual quint8 opcode(void) const { return 0x08; }

    inline quint32 clusterId(void) { return m_clusterId; }

protected:

    quint32 m_clusterId;

};

namespace Actions
{
    class Status : public ActionObject
    {

    public:

        Status(void) : ActionObject("status", Clusters::OnOff::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    class Level : public ActionObject
    {

    public:

        Level(void) : ActionObject("level", Clusters::LevelControl::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    class ColorHS : public ActionObject
    {

    public:

        ColorHS(void) : ActionObject("color", Clusters::ColorControl::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    class ColorTemperature : public ActionObject
    {

    public:

        ColorTemperature(void) : ActionObject("colorTemperature", Clusters::ColorControl::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    class Lock : public ActionObject
    {

    public:

        Lock(void) : ActionObject("lock", Clusters::DoorLock::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    class CoverStatus : public ActionObject
    {

    public:

        CoverStatus(void) : ActionObject("cover", Clusters::WindowCovering::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    class CoverPosition : public ActionObject
    {

    public:

        CoverPosition(void) : ActionObject("coverPosition", Clusters::WindowCovering::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };

    // Matter §1.5.6.3 StartUpOnOff: nullable enum8 (0=Off, 1=On, 2=Toggle, null=preserve previous). written via
    // WriteRequest, not InvokeRequest — unlike on/off/toggle which are commands. consumer-facing labels follow
    // expose.json: "off"/"on"/"toggle"/"previous"
    class PowerOnStatus : public ActionObject
    {

    public:

        PowerOnStatus(void) : ActionObject("powerOnStatus", Clusters::OnOff::Id) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;
        quint8 opcode(void) const override { return 0x06; } // WriteRequest

    };
}

#endif
