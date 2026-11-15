#include "color.h"
#include "property.h"

static quint8 switchPressCount(const MatterTLV::Element &data)
{
    quint8 count = 0;

    // MultiPressComplete event data tag 1 is total number of presses counted
    for (int i = 0; i < data.children.count(); i++)
    {
        if (data.children.at(i).tag != 1)
            continue;

        count = static_cast <quint8> (data.children.at(i).value.toUInt());
    }

    return count;
}

void Properties::Status::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::OnOff::Attributes::OnOff)
        return;

    m_value = data.value.toBool() ? "on" : "off";
}

void Properties::Level::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::LevelControl::Attributes::CurrentLevel)
        return;

    m_value = qMin(data.value.toUInt() * 0xFF / 0xFE, 0xFFu); // 0xFE is maximum level
}

void Properties::ColorHS::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    Color color(0, 0, 0);

    switch (attributeId)
    {
        case Clusters::ColorControl::Attributes::CurrentHue:
            m_hue = static_cast <quint8> (data.value.toUInt());
            m_hueReceived = true;
            break;

        case Clusters::ColorControl::Attributes::CurrentSaturation:
            m_saturation = static_cast <quint8> (data.value.toUInt());
            m_saturationReceived = true;
            break;

        default:
            return;
    }

    if (!m_hueReceived || !m_saturationReceived)
        return;

    color = Color::fromHS(m_hue / static_cast <double> (0xFE), m_saturation / static_cast <double> (0xFE));
    m_value = QList <QVariant> {static_cast <int> (color.r() * 0xFF), static_cast <int> (color.g() * 0xFF), static_cast <int> (color.b() * 0xFF)};
}

void Properties::ColorTemperature::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ColorControl::Attributes::ColorTemperatureMireds)
        return;

    m_value = data.value.toUInt();
}

void Properties::ColorMode::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ColorControl::Attributes::ColorMode)
        return;

    m_value = data.value.toUInt() != 2; // true for HS or XY, false for color temperature
}

void Properties::Battery::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::PowerSource::Attributes::BatPercentRemaining)
        return;

    m_value = data.value.toDouble() / 2;
}

void Properties::Temperature::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::TemperatureMeasurement::Attributes::MeasuredValue)
        return;

    m_value = data.value.toDouble() / 100;
}

void Properties::Humidity::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue)
        return;

    m_value = data.value.toDouble() / 100;
}

void Properties::Voltage::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::Voltage && attributeId != Clusters::ElectricalPowerMeasurement::Attributes::RMSVoltage)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Properties::Current::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::ActiveCurrent && attributeId != Clusters::ElectricalPowerMeasurement::Attributes::RMSCurrent)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Properties::Power::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::ActivePower)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Properties::Frequency::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalPowerMeasurement::Attributes::Frequency)
        return;

    m_value = data.value.toLongLong() / 1000.0;
}

void Properties::Energy::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported)
        return;

    // energy measurement structure tag 0 is energy value
    for (int i = 0; i < data.children.count(); i++)
    {
        if (data.children.at(i).tag)
            continue;

        m_value = data.children.at(i).value.toLongLong() / 1000.0;
        break;
    }
}

void Properties::Lock::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::DoorLock::Attributes::LockState)
        return;

    m_value = data.value.toUInt() == 1; // TODO: check not fully locked and unlatched states
}

void Properties::CoverPosition::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::WindowCovering::Attributes::CurrentPositionLiftPercent100ths)
        return;

    m_value = data.value.toUInt() / 100; // TODO: check with real device
}

void Properties::WaterLeak::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::BooleanState::Attributes::StateValue)
        return;

    m_value = data.value.toBool();
}

void Properties::Contact::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::BooleanState::Attributes::StateValue)
        return;

    m_value = !data.value.toBool(); // state value is true when contact is closed
}

void Properties::Occupancy::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::OccupancySensing::Attributes::Occupancy)
        return;

    m_value = (data.value.toUInt() & 0x01) != 0;
}

void Properties::SwitchAction::parseEvent(quint32 eventId, const MatterTLV::Element &data)
{
    quint32 features = meta("switchFeatures").toUInt();
    bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && static_cast <quint8> (meta("switchMultiPressMax").toUInt()) > 5;

    switch (eventId)
    {
        case Clusters::Switch::Events::SwitchLatched:
            m_value = "latched";
            break;

        case Clusters::Switch::Events::InitialPress:

            // only encoders subscribe to initial press, for buttons it's just noise
            if (encoder)
                m_value = "start";

            break;

        case Clusters::Switch::Events::ShortRelease:

            // with MSM feature press count comes with multi press complete event
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
            quint8 count = switchPressCount(data);

            if (encoder)
            {
                m_value = "stop";
                break;
            }

            switch (count)
            {
                case 0:  break;
                case 1:  m_value = "singleClick"; break;
                case 2:  m_value = "doubleClick"; break;
                case 3:  m_value = "tripleClick"; break;
                default: m_value = "multipleClick"; break;
            }

            break;
        }
    }
}

void Properties::SwitchCount::parseEvent(quint32 eventId, const MatterTLV::Element &data)
{
    quint8 count = switchPressCount(data);

    if (eventId != Clusters::Switch::Events::MultiPressComplete || !count)
        return;

    m_value = count;
}

void Properties::PowerOnStatus::parseAttribute(quint32 attributeId, const MatterTLV::Element &data)
{
    if (attributeId != Clusters::OnOff::Attributes::StartUpOnOff)
        return;

    if (data.type == MatterTLV::Type::Null)
    {
        m_value = "previous"; // null means previous state
        return;
    }

    switch (data.value.toUInt())
    {
        case 0: m_value = "off"; break;
        case 1: m_value = "on"; break;
        case 2: m_value = "toggle"; break;
    }
}
