#ifndef PROPERTY_H
#define PROPERTY_H

#include "clusters.h"
#include "endpoint.h"
#include "tlv.h"

class PropertyObject;
typedef QSharedPointer <PropertyObject> Property;

class PropertyObject : public AbstractMetaObject
{

public:

    PropertyObject(const QString &name, quint32 clusterId) :
        AbstractMetaObject(name), m_clusterId(clusterId), m_multiple(false) {}

    virtual ~PropertyObject(void) {}
    virtual void parseAttribute(quint32, const MatterTLV::Element &) {}
    virtual void parseEvent(quint32, const MatterTLV::Element &) {}

    inline quint32 clusterId(void) { return m_clusterId; }

    inline bool multiple(void) { return m_multiple; }
    inline void setMultiple(bool value) { m_multiple = value; }

    inline QVariant value(void) { return m_value; }
    inline void clearValue(void) { m_value.clear(); }

protected:

    quint32 m_clusterId;
    bool m_multiple;
    QVariant m_value;

};

namespace Properties
{
    class Status : public PropertyObject
    {

    public:

        Status(void) : PropertyObject("status", Clusters::OnOff::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Level : public PropertyObject
    {

    public:

        Level(void) : PropertyObject("level", Clusters::LevelControl::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class ColorHS : public PropertyObject
    {

    public:

        ColorHS(void) : PropertyObject("color", Clusters::ColorControl::Id), m_hue(0), m_saturation(0), m_hueReceived(false), m_saturationReceived(false) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    private:

        quint8 m_hue, m_saturation;
        bool m_hueReceived, m_saturationReceived;

    };

    class ColorTemperature : public PropertyObject
    {

    public:

        ColorTemperature(void) : PropertyObject("colorTemperature", Clusters::ColorControl::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class ColorMode : public PropertyObject
    {

    public:

        ColorMode(void) : PropertyObject("colorMode", Clusters::ColorControl::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Battery : public PropertyObject
    {

    public:

        Battery(void) : PropertyObject("battery", Clusters::PowerSource::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Temperature : public PropertyObject
    {

    public:

        Temperature(void) : PropertyObject("temperature", Clusters::TemperatureMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Humidity : public PropertyObject
    {

    public:

        Humidity(void) : PropertyObject("humidity", Clusters::RelativeHumidityMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Voltage : public PropertyObject
    {

    public:

        Voltage(void) : PropertyObject("voltage", Clusters::ElectricalPowerMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Current : public PropertyObject
    {

    public:

        Current(void) : PropertyObject("current", Clusters::ElectricalPowerMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Power : public PropertyObject
    {

    public:

        Power(void) : PropertyObject("power", Clusters::ElectricalPowerMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Frequency : public PropertyObject
    {

    public:

        Frequency(void) : PropertyObject("frequency", Clusters::ElectricalPowerMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Energy : public PropertyObject
    {

    public:

        Energy(void) : PropertyObject("energy", Clusters::ElectricalEnergyMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Lock : public PropertyObject
    {

    public:

        Lock(void) : PropertyObject("lock", Clusters::DoorLock::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class CoverPosition : public PropertyObject
    {

    public:

        CoverPosition(void) : PropertyObject("coverPosition", Clusters::WindowCovering::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class WaterLeak : public PropertyObject
    {

    public:

        WaterLeak(void) : PropertyObject("waterLeak", Clusters::BooleanState::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Contact : public PropertyObject
    {

    public:

        Contact(void) : PropertyObject("contact", Clusters::BooleanState::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Occupancy : public PropertyObject
    {

    public:

        Occupancy(void) : PropertyObject("occupancy", Clusters::OccupancySensing::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class SwitchAction : public PropertyObject
    {

    public:

        SwitchAction(void) : PropertyObject("action", Clusters::Switch::Id) {}
        void parseEvent(quint32 eventId, const MatterTLV::Element &data) override;

    };

    class SwitchCount : public PropertyObject
    {

    public:

        SwitchCount(void) : PropertyObject("count", Clusters::Switch::Id) {}
        void parseEvent(quint32 eventId, const MatterTLV::Element &data) override;

    };

    class PowerOnStatus : public PropertyObject
    {

    public:

        PowerOnStatus(void) : PropertyObject("powerOnStatus", Clusters::OnOff::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };
}

#endif
