#ifndef ACTION_H
#define ACTION_H

#include "clusters.h"
#include "endpoint.h"
#include "message.h"

class ActionObject;
typedef QSharedPointer <ActionObject> Action;

class ActionObject : public AbstractMetaObject
{

public:

    ActionObject(const QString &name, quint32 clusterId, MatterProtocol::InteractionModelOpcode opcode = MatterProtocol::InteractionModelOpcode::InvokeRequest) :
        AbstractMetaObject(name), m_clusterId(clusterId), m_opcode(opcode) {}

    virtual ~ActionObject(void) {}
    virtual QByteArray request(quint16 endpointId, const QVariant &data) = 0;

    inline quint32 clusterId(void) { return m_clusterId; }
    inline MatterProtocol::InteractionModelOpcode opcode(void) { return m_opcode; }

protected:

    quint32 m_clusterId;
    MatterProtocol::InteractionModelOpcode m_opcode;

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

    class PowerOnStatus : public ActionObject
    {

    public:

        PowerOnStatus(void) : ActionObject("powerOnStatus", Clusters::OnOff::Id, MatterProtocol::InteractionModelOpcode::WriteRequest) {}
        QByteArray request(quint16 endpointId, const QVariant &data) override;

    };
}

#endif
