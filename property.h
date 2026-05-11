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

    // UNTESTED: written from Matter spec §3.2.7, no XY-only test device on hand to validate the X/Y → RGB
    // conversion or the 0..0xFEFF normalization. mirror of ColorHS for caps bit 0x0008
    class ColorXY : public PropertyObject
    {

    public:

        ColorXY(void) : PropertyObject("color", Clusters::ColorControl::Id), m_haveX(false), m_haveY(false), m_x(0), m_y(0) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    private:

        bool m_haveX, m_haveY;
        quint16 m_x, m_y;

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

    // UNTESTED: written from Matter spec §5.2 (DoorLock cluster), no real lock to verify the LockState enum
    // mapping. spec values: 0=NotFullyLocked, 1=Locked, 2=Unlocked, 3=Unlatched
    class Lock : public PropertyObject
    {

    public:

        Lock(void) : PropertyObject("lock", Clusters::DoorLock::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    // UNTESTED: Matter spec §5.3 WindowCovering reports CurrentPositionLiftPercent100ths (uint16, 0..10000
    // representing 0.00..100.00%); we expose 0..100 to consumers. no real cover on hand to verify
    class CoverPosition : public PropertyObject
    {

    public:

        CoverPosition(void) : PropertyObject("coverPosition", Clusters::WindowCovering::Id) {}
        void parseAttribute(quint32 attributeId, const MatterTLV::Element &data) override;

    };

    // BooleanState (Matter §1.7) is the generic binary-state cluster reused by multiple device types. semantics
    // come from the endpoint's DeviceTypeList: water leak detector reports true=leak, contact sensor reports
    // true=closed. Contact inverts so that "true" externally consistently means "abnormal/active/open"
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
}

#endif
