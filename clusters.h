// NOT REWIEWED

#ifndef CLUSTERS_H
#define CLUSTERS_H

#include <QtGlobal>

/*
    Matter Cluster IDs, Attribute IDs, Command IDs
    (spec section 7, Cluster Library)
*/

namespace Clusters
{
    // --- Utility Clusters ---

    namespace Descriptor // 0x001D
    {
        const quint32 Id = 0x001D;

        namespace Attributes
        {
            const quint32 DeviceTypeList  = 0x0000;
            const quint32 ServerList      = 0x0001;
            const quint32 ClientList      = 0x0002;
            const quint32 PartsList       = 0x0003;
        }
    }

    namespace BasicInformation // 0x0028
    {
        const quint32 Id = 0x0028;

        namespace Attributes
        {
            const quint32 DataModelRevision    = 0x0000;
            const quint32 VendorName           = 0x0001;
            const quint32 VendorID             = 0x0002;
            const quint32 ProductName          = 0x0003;
            const quint32 ProductID            = 0x0004;
            const quint32 NodeLabel            = 0x0005;
            const quint32 Location             = 0x0006;
            const quint32 HardwareVersion      = 0x0007;
            const quint32 HardwareVersionString = 0x0008;
            const quint32 SoftwareVersion      = 0x0009;
            const quint32 SoftwareVersionString = 0x000A;
            const quint32 SerialNumber         = 0x000F;
            const quint32 UniqueID             = 0x0012;
        }
    }

    namespace NetworkCommissioning // 0x0031
    {
        const quint32 Id = 0x0031;

        namespace Attributes
        {
            const quint32 FeatureMap                 = 0xFFFC;
        }

        namespace Commands
        {
            const quint32 AddOrUpdateWiFiNetwork     = 0x0002;
            const quint32 AddOrUpdateThreadNetwork   = 0x0003;
            const quint32 NetworkConfigResponse      = 0x0005;
            const quint32 ConnectNetwork             = 0x0006;
            const quint32 ConnectNetworkResponse     = 0x0007;
        }
    }

    // --- General Commissioning ---

    namespace GeneralCommissioning // 0x0030
    {
        const quint32 Id = 0x0030;

        namespace Attributes
        {
            const quint32 Breadcrumb            = 0x0000;
            const quint32 BasicCommissioningInfo = 0x0001;
            const quint32 RegulatoryConfig      = 0x0002;
            const quint32 LocationCapability    = 0x0003;
        }

        namespace Commands
        {
            const quint32 ArmFailSafe         = 0x0000;
            const quint32 ArmFailSafeResponse = 0x0001;
            const quint32 SetRegulatoryConfig = 0x0002;
            const quint32 SetRegulatoryConfigResponse = 0x0003;
            const quint32 CommissioningComplete = 0x0004;
            const quint32 CommissioningCompleteResponse = 0x0005;
        }
    }

    namespace OperationalCredentials // 0x003E
    {
        const quint32 Id = 0x003E;

        namespace Attributes
        {
            const quint32 NOCs                  = 0x0000;
            const quint32 Fabrics               = 0x0001;
            const quint32 SupportedFabrics      = 0x0002;
            const quint32 CommissionedFabrics   = 0x0003;
            const quint32 TrustedRootCertificates = 0x0004;
            const quint32 CurrentFabricIndex    = 0x0005;
        }

        namespace Commands
        {
            const quint32 AttestationRequest    = 0x0000;
            const quint32 AttestationResponse   = 0x0001;
            const quint32 CertificateChainRequest = 0x0002;
            const quint32 CertificateChainResponse = 0x0003;
            const quint32 CSRRequest            = 0x0004;
            const quint32 CSRResponse           = 0x0005;
            const quint32 AddNOC                = 0x0006;
            const quint32 UpdateNOC             = 0x0007;
            const quint32 NOCResponse           = 0x0008;
            const quint32 UpdateFabricLabel     = 0x0009;
            const quint32 RemoveFabric          = 0x000A;
            const quint32 AddTrustedRootCertificate = 0x000B;
        }
    }

    namespace AdministratorCommissioning // 0x003C
    {
        const quint32 Id = 0x003C;

        namespace Commands
        {
            const quint32 OpenCommissioningWindow      = 0x0000;
            const quint32 OpenBasicCommissioningWindow  = 0x0001;
            const quint32 RevokeCommissioning           = 0x0002;
        }
    }

    // --- Application Clusters ---

    namespace Identify // 0x0003
    {
        const quint32 Id = 0x0003;

        namespace Commands
        {
            const quint32 Identify = 0x0000;
        }
    }

    namespace OnOff // 0x0006
    {
        const quint32 Id = 0x0006;

        namespace Attributes
        {
            const quint32 OnOff        = 0x0000;
            const quint32 StartUpOnOff = 0x4003; // power-on default (LT feature)
            const quint32 FeatureMap   = 0xFFFC;
        }

        namespace Commands
        {
            const quint32 Off    = 0x0000;
            const quint32 On     = 0x0001;
            const quint32 Toggle = 0x0002;
        }

        // Matter spec §1.5.4 OnOff FeatureMap; LT makes StartUpOnOff mandatory
        namespace Features
        {
            const quint32 LT = 1 << 0; // Lighting
            const quint32 DF = 1 << 1; // DeadFrontBehavior
        }
    }

    namespace Switch // 0x003B
    {
        const quint32 Id = 0x003B;

        namespace Attributes
        {
            const quint32 NumberOfPositions = 0x0000;
            const quint32 CurrentPosition   = 0x0001;
            const quint32 MultiPressMax     = 0x0002;
            const quint32 FeatureMap        = 0xFFFC;
        }

        // Matter §1.13 — events depend on FeatureMap bits LS/MS/MSR/MSL/MSM/AS
        namespace Events
        {
            const quint32 SwitchLatched      = 0x00; // LS (Latching Switch)
            const quint32 InitialPress       = 0x01; // MS (Momentary Switch)
            const quint32 LongPress          = 0x02; // MSL
            const quint32 ShortRelease       = 0x03; // MSR (without AS)
            const quint32 LongRelease        = 0x04; // MSL
            const quint32 MultiPressOngoing  = 0x05; // MSM
            const quint32 MultiPressComplete = 0x06; // MSM
        }

        namespace Features
        {
            const quint32 LS  = 1 << 0;
            const quint32 MS  = 1 << 1;
            const quint32 MSR = 1 << 2;
            const quint32 MSL = 1 << 3;
            const quint32 MSM = 1 << 4;
            const quint32 AS  = 1 << 5;
        }
    }

    namespace LevelControl // 0x0008
    {
        const quint32 Id = 0x0008;

        namespace Attributes
        {
            const quint32 CurrentLevel  = 0x0000;
            const quint32 MinLevel      = 0x0002;
            const quint32 MaxLevel      = 0x0003;
            const quint32 OnLevel       = 0x0011;
        }

        namespace Commands
        {
            const quint32 MoveToLevel             = 0x0000;
            const quint32 Move                    = 0x0001;
            const quint32 Step                    = 0x0002;
            const quint32 Stop                    = 0x0003;
            const quint32 MoveToLevelWithOnOff    = 0x0004;
        }
    }

    namespace ColorControl // 0x0300
    {
        const quint32 Id = 0x0300;

        namespace Attributes
        {
            const quint32 CurrentHue          = 0x0000;
            const quint32 CurrentSaturation   = 0x0001;
            const quint32 CurrentX            = 0x0003;
            const quint32 CurrentY            = 0x0004;
            const quint32 ColorTemperatureMireds        = 0x0007;
            const quint32 ColorMode                     = 0x0008;
            const quint32 ColorCapabilities             = 0x400A;
            const quint32 ColorTempPhysicalMinMireds    = 0x400B;
            const quint32 ColorTempPhysicalMaxMireds    = 0x400C;
        }

        namespace Commands
        {
            const quint32 MoveToHueAndSaturation  = 0x0006;
            const quint32 MoveToColor             = 0x0007;
            const quint32 MoveToColorTemperature  = 0x000A;
        }
    }

    namespace PowerSource // 0x002F
    {
        const quint32 Id = 0x002F;

        namespace Attributes
        {
            const quint32 BatVoltage          = 0x000B;
            const quint32 BatPercentRemaining = 0x000C;
            const quint32 BatChargeLevel      = 0x000E;
        }
    }

    namespace TemperatureMeasurement // 0x0402
    {
        const quint32 Id = 0x0402;

        namespace Attributes
        {
            const quint32 MeasuredValue    = 0x0000;
            const quint32 MinMeasuredValue = 0x0001;
            const quint32 MaxMeasuredValue = 0x0002;
        }
    }

    namespace RelativeHumidityMeasurement // 0x0405
    {
        const quint32 Id = 0x0405;

        namespace Attributes
        {
            const quint32 MeasuredValue    = 0x0000;
            const quint32 MinMeasuredValue = 0x0001;
            const quint32 MaxMeasuredValue = 0x0002;
        }
    }

    namespace ElectricalPowerMeasurement // 0x0090
    {
        const quint32 Id = 0x0090;

        namespace Attributes
        {
            const quint32 Voltage       = 0x0004;
            const quint32 ActiveCurrent = 0x0005;
            const quint32 ActivePower   = 0x0008;
            // AC-specific RMS variants (Matter spec §2.13.5); peer chooses one set based on AC vs DC mode
            const quint32 RMSVoltage    = 0x000B;
            const quint32 RMSCurrent    = 0x000C;
            const quint32 Frequency     = 0x000E;
            const quint32 FeatureMap    = 0xFFFC;
        }

        // Matter spec §2.13.4 ElectricalPowerMeasurement FeatureMap
        namespace Features
        {
            const quint32 DIRC = 1 << 0; // DirectCurrent
            const quint32 ALTC = 1 << 1; // AlternatingCurrent
            const quint32 POLY = 1 << 2; // PolyphasePower
            const quint32 HARM = 1 << 3; // Harmonics
            const quint32 PWRQ = 1 << 4; // PowerQuality
        }
    }

    namespace ElectricalEnergyMeasurement // 0x0091
    {
        const quint32 Id = 0x0091;

        namespace Attributes
        {
            const quint32 CumulativeEnergyImported = 0x0001;
        }
    }

    namespace BooleanState // 0x0045
    {
        const quint32 Id = 0x0045;

        namespace Attributes
        {
            const quint32 StateValue = 0x0000;
        }
    }

    // Matter device types (spec §10) — endpoint Descriptor's DeviceTypeList discriminates what a generic
    // cluster like BooleanState semantically means on this endpoint (contact vs leak vs freeze vs rain)
    namespace DeviceTypes
    {
        const quint32 ContactSensor       = 0x0015;
        const quint32 WaterFreezeDetector = 0x0041;
        const quint32 WaterLeakDetector   = 0x0043;
        const quint32 RainSensor          = 0x0044;
    }

    namespace OccupancySensing // 0x0406
    {
        const quint32 Id = 0x0406;

        namespace Attributes
        {
            const quint32 Occupancy        = 0x0000;
            const quint32 OccupancySensorType = 0x0001;
        }
    }

    namespace IlluminanceMeasurement // 0x0400
    {
        const quint32 Id = 0x0400;

        namespace Attributes
        {
            const quint32 MeasuredValue    = 0x0000;
            const quint32 MinMeasuredValue = 0x0001;
            const quint32 MaxMeasuredValue = 0x0002;
        }
    }

    namespace PressureMeasurement // 0x0403
    {
        const quint32 Id = 0x0403;

        namespace Attributes
        {
            const quint32 MeasuredValue    = 0x0000;
            const quint32 MinMeasuredValue = 0x0001;
            const quint32 MaxMeasuredValue = 0x0002;
        }
    }

    namespace DoorLock // 0x0101
    {
        const quint32 Id = 0x0101;

        namespace Attributes
        {
            const quint32 LockState  = 0x0000;
            const quint32 LockType   = 0x0001;
        }

        namespace Commands
        {
            const quint32 LockDoor   = 0x0000;
            const quint32 UnlockDoor = 0x0001;
        }
    }

    namespace WindowCovering // 0x0102
    {
        const quint32 Id = 0x0102;

        namespace Attributes
        {
            const quint32 Type                            = 0x0000;
            const quint32 CurrentPositionLiftPercent100ths = 0x000E;
            const quint32 CurrentPositionTiltPercent100ths = 0x000F;
            const quint32 TargetPositionLiftPercent100ths  = 0x000B;
        }

        namespace Commands
        {
            const quint32 UpOrOpen   = 0x0000;
            const quint32 DownOrClose = 0x0001;
            const quint32 StopMotion = 0x0002;
            const quint32 GoToLiftPercentage = 0x0005;
        }
    }

    namespace Thermostat // 0x0201
    {
        const quint32 Id = 0x0201;

        namespace Attributes
        {
            const quint32 LocalTemperature       = 0x0000;
            const quint32 OccupiedCoolingSetpoint = 0x0011;
            const quint32 OccupiedHeatingSetpoint = 0x0012;
            const quint32 SystemMode              = 0x001C;
        }

        namespace Commands
        {
            const quint32 SetpointRaiseLower = 0x0000;
        }
    }
}

#endif
