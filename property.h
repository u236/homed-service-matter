#ifndef PROPERTY_H
#define PROPERTY_H

#include <QSharedPointer>
#include <QVariant>
#include "clusters.h"
#include "endpoint.h"
#include "tlv.h"

class PropertyObject;
typedef QSharedPointer <PropertyObject> Property;

class PropertyObject : public AbstractMetaObject
{

public:

    PropertyObject(const QString &name, quint32 clusterId) : AbstractMetaObject(name), m_clusterId(clusterId), m_multiple(false) {}

    virtual ~PropertyObject(void) {}
    virtual void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) { Q_UNUSED(attributeId); Q_UNUSED(data); }
    virtual void parseEvent(quint32 eventId, const MatterTLV::Element &data) { Q_UNUSED(eventId); Q_UNUSED(data); }

    inline QVariant value(void) { return m_value; }
    inline void clearValue(void) { m_value.clear(); }

    inline quint32 clusterId(void) { return m_clusterId; }
    inline bool multiple(void) { return m_multiple; }
    inline void setMultiple(bool value) { m_multiple = value; }

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

        ColorHS(void) : PropertyObject("color", Clusters::ColorControl::Id), m_haveHue(false), m_haveSat(false), m_hue(0), m_sat(0) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    private:

        // partial HS state stays inside the property so the endpoint status map doesn't carry colorH/colorS scratch
        // keys; both halves arrive in the same ReportData but as separate AttributeReports
        bool m_haveHue, m_haveSat;
        quint8 m_hue, m_sat;

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

    class Power : public PropertyObject
    {

    public:

        Power(void) : PropertyObject("power", Clusters::ElectricalPowerMeasurement::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    class Energy : public PropertyObject
    {

    public:

        Energy(void) : PropertyObject("energy", Clusters::ElectricalEnergyMeasurement::Id) {}
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
}

#endif
