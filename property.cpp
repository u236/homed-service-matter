#include "color.h"
#include "property.h"

namespace Properties
{

void Status::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::OnOff::Attributes::OnOff)
        return;

    m_value = data.value.toBool() ? "on" : "off";
}

void Level::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::LevelControl::Attributes::CurrentLevel)
        return;

    // peer reports CurrentLevel on the 0..0xFE Matter scale; we expose 0..0xFF to consumers — same scaling
    // sendCommand uses in the opposite direction
    m_value = qMin(data.value.toUInt() * 0xFF / 0xFE, 0xFFu);
}

void ColorHS::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    switch (attributeId)
    {
        case Clusters::ColorControl::Attributes::CurrentHue:
            m_hue = static_cast <quint8> (data.value.toUInt());
            m_haveHue = true;
            break;

        case Clusters::ColorControl::Attributes::CurrentSaturation:
            m_sat = static_cast <quint8> (data.value.toUInt());
            m_haveSat = true;
            break;

        default:
            return;
    }

    if (!m_haveHue || !m_haveSat)
        return;

    Color color = Color::fromHS(m_hue / static_cast <double> (0xFE), m_sat / static_cast <double> (0xFE));
    m_value = QVariant(QList <QVariant> {static_cast <int> (color.r() * 0xFF), static_cast <int> (color.g() * 0xFF), static_cast <int> (color.b() * 0xFF)});
}

void ColorXY::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    // UNTESTED: CurrentX/CurrentY are uint16 normalized so that 0xFEFF represents 1.0 in CIE xy space
    // (Matter §3.2.7.5). Color::fromXY expects normalized 0.0..1.0 doubles
    switch (attributeId)
    {
        case Clusters::ColorControl::Attributes::CurrentX:
            m_x = static_cast <quint16> (data.value.toUInt());
            m_haveX = true;
            break;

        case Clusters::ColorControl::Attributes::CurrentY:
            m_y = static_cast <quint16> (data.value.toUInt());
            m_haveY = true;
            break;

        default:
            return;
    }

    if (!m_haveX || !m_haveY)
        return;

    Color color = Color::fromXY(m_x / static_cast <double> (0xFEFF), m_y / static_cast <double> (0xFEFF));
    m_value = QVariant(QList <QVariant> {static_cast <int> (color.r() * 0xFF), static_cast <int> (color.g() * 0xFF), static_cast <int> (color.b() * 0xFF)});
}

void ColorTemperature::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ColorControl::Attributes::ColorTemperatureMireds)
        return;

    m_value = data.value.toUInt();
}

void Lock::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::DoorLock::Attributes::LockState)
        return;

    // UNTESTED: LockState enum (Matter §5.2.5.5): 0=NotFullyLocked, 1=Locked, 2=Unlocked, 3=Unlatched.
    // we report "locked" only on value=1 — partial/unlatched states fall to false until proven otherwise
    m_value = data.value.toUInt() == 1;
}

void CoverPosition::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::WindowCovering::Attributes::CurrentPositionLiftPercent100ths)
        return;

    // UNTESTED: peer reports 0..10000 in 0.01% units, scale to 0..100 to match what Actions::CoverPosition
    // accepts on the way down (consumer-facing percent)
    m_value = data.value.toUInt() / 100;
}

void ColorMode::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ColorControl::Attributes::ColorMode)
        return;

    // ColorMode 0=HS, 1=XY, 2=ColorTemperature; we report a bool: "is this a chromatic color (vs CT)?"
    m_value = data.value.toUInt() != 2;
}

void Battery::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::PowerSource::Attributes::BatPercentRemaining)
        return;

    // BatPercentRemaining reports half-percentage units, divide by 2 to get 0..100%
    m_value = data.value.toDouble() / 2.0;
}

void Temperature::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::TemperatureMeasurement::Attributes::MeasuredValue)
        return;

    m_value = data.value.toDouble() / 100.0;
}

void Humidity::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue)
        return;

    m_value = data.value.toDouble() / 100.0;
}

void Voltage::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::Voltage)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Current::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::ActiveCurrent)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Power::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::ActivePower)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Energy::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported)
        return;

    // CumulativeEnergyImported is an EnergyMeasurementStruct; tag 0 is the energy field in mWh
    for (const MatterTLV::Element &child : data.children)
    {
        if (child.tag != 0)
            continue;

        m_value = child.value.toLongLong() / 1000.0;
        return;
    }
}

void SwitchAction::parseEvent(quint32 eventId, const MatterTLV::Element &data)
{
    quint32 features = meta("switchFeatures").toUInt();
    quint8 multiPressMax = static_cast <quint8> (meta("switchMultiPressMax").toUInt());
    // encoder heuristic: high MultiPressMax + no MSL means MultiPressComplete count is detents, not clicks —
    // emit start/stop semantics instead of singleClick/doubleClick/etc
    bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && multiPressMax > 5;

    switch (eventId)
    {
        case Clusters::Switch::Events::SwitchLatched:
            m_value = "latched";
            break;

        case Clusters::Switch::Events::InitialPress:
            // only encoder endpoints subscribe to InitialPress; for buttons the ShortRelease/MultiPressComplete
            // path is what matters and InitialPress is just noise
            if (encoder)
                m_value = "start";
            break;

        case Clusters::Switch::Events::ShortRelease:
            // ShortRelease only fires on MSR endpoints without MSM (Matter §1.13.6.4); for MSM the count comes
            // through MultiPressComplete and emitting singleClick here would duplicate the doubleClick path
            if (!(features & Clusters::Switch::Features::MSM))
                m_value = "singleClick";
            break;

        case Clusters::Switch::Events::LongPress:
            m_value = "hold";
            break;

        case Clusters::Switch::Events::LongRelease:
            m_value = "release";
            break;

        case Clusters::Switch::Events::MultiPressComplete:
        {
            if (encoder)
            {
                m_value = "stop";
                break;
            }

            quint8 count = 0;

            for (const MatterTLV::Element &child : data.children)
            {
                if (child.tag == 1)
                    count = static_cast <quint8> (child.value.toUInt());
            }

            switch (count)
            {
                case 1: m_value = "singleClick"; break;
                case 2: m_value = "doubleClick"; break;
                case 3: m_value = "tripleClick"; break;
                default:
                    if (count > 0)
                        m_value = "multipleClick";
                    break;
            }

            break;
        }
    }
}

void SwitchCount::parseEvent(quint32 eventId, const MatterTLV::Element &data)
{
    if (eventId != Clusters::Switch::Events::MultiPressComplete)
        return;

    // MultiPressComplete data (Matter §1.13.6.6): tag 0=PreviousPosition, tag 1=TotalNumberOfPressesCounted
    for (const MatterTLV::Element &child : data.children)
    {
        if (child.tag != 1)
            continue;

        quint8 count = static_cast <quint8> (child.value.toUInt());

        if (count > 0)
            m_value = count;

        return;
    }
}

}
