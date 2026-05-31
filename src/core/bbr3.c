/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Bottleneck Bandwidth and RTT (BBR) congestion control.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "bbr3.c.clog.h"
#endif

typedef enum BBR_STATE {

    BBR_STATE_STARTUP,

    BBR_STATE_DRAIN,

    BBR_STATE_PROBE_BW,

    BBR_STATE_PROBE_RTT

} BBR_STATE;

typedef enum RECOVERY_STATE {

    RECOVERY_STATE_NOT_RECOVERY = 0,

    RECOVERY_STATE_CONSERVATIVE = 1,

    RECOVERY_STATE_GROWTH = 2,

} RECOVERY_STATE;

//
// Bandwidth is measured as (bytes / BW_UNIT) per second
//
#define BW_UNIT 8 // 1 << 3

//
// Gain is measured as (1 / GAIN_UNIT)
//
#define GAIN_UNIT 256 // 1 << 8

//
// The length of the gain cycle
//
#define GAIN_CYCLE_LENGTH 8

static const uint64_t kQuantaFactor = 3;

static const uint32_t kMinCwndInMss = 4;

static const uint32_t kDefaultRecoveryCwndInMss = 2000;

static const uint64_t kMicroSecsInSec = 1000000;

static const uint64_t kMilliSecsInSec = 1000;

static const uint64_t kLowPacingRateThresholdBytesPerSecond = 1200ULL * 1000;

static const uint64_t kHighPacingRateThresholdBytesPerSecond = 24ULL * 1000 * 1000;

static const uint32_t kHighGain = GAIN_UNIT * 2885 / 1000 + 1; // 2/ln(2)

static const uint32_t kDrainGain = GAIN_UNIT * 1000 / 2885; // 1/kHighGain

//
// Cwnd gain during ProbeBw
//
static const uint32_t kCwndGain = GAIN_UNIT * 2;

//
// The expected of bandwidth growth in each round trip time during STARTUP
//
static const uint32_t kStartupGrowthTarget = GAIN_UNIT * 5 / 4;

//
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kStartupGrowthTarget
//
static const uint8_t kStartupSlowGrowRoundLimit = 3;

//
// The cycle of gains used during the PROBE_BW stage
//
static const uint32_t kPacingGain[GAIN_CYCLE_LENGTH] = {
    GAIN_UNIT * 5 / 4,
    GAIN_UNIT * 3 / 4,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT
};

//
// During ProbeRtt, we need to stay in low inflight condition for at least kProbeRttTimeInUs
//
static const uint32_t kProbeRttTimeInUs = 200 * 1000;

//
// Time until a MinRtt measurement is expired.
//
static const uint32_t kBbr3MinRttExpirationInMicroSecs = S_TO_US(10);

static const uint32_t kBbr3MaxBandwidthFilterLen = 10;

static const uint32_t kBbr3MaxAckHeightFilterLen = 10;

//
// Phase A: BBRv1 loss-response patch (compile-time toggle for easy revert).
//
// Stock BBRv1 collapses the congestion window on links with sparse random loss
// (~1-2%): every loss event subtracts all lost bytes from the recovery window
// and floors it at kMinCwndInMss (4*MSS = ~5.9 KB), which throttles throughput
// to near zero and never recovers. This patch makes the loss response tolerant
// of sub-threshold (random) loss and decays gently instead of cliff-diving.
//
// IMPORTANT: this intentionally does NOT change kMinCwndInMss, because PROBE_RTT
// deliberately drains to 4*MSS to sample min-RTT (see GetCongestionWindow). The
// higher floor below applies only to the loss/recovery path.
//
// Set BBR_PHASE_A_LOSS_PATCH to 0 to restore stock BBRv1 behavior.
//
#ifndef BBR_PHASE_A_LOSS_PATCH
#define BBR_PHASE_A_LOSS_PATCH 1
#endif

#if BBR_PHASE_A_LOSS_PATCH
//
// Recovery-window floor, in MSS, for the loss/recovery path only. 16*MSS ~= 23 KB.
//
static const uint32_t kBbr3RecoveryFloorPackets = 16;
//
// Per-event loss tolerance: if the bytes lost in a single loss event are below
// this percentage of the pre-loss bytes-in-flight, treat it as random loss and
// leave the recovery window unchanged (only enforce the floor).
//
static const uint32_t kBbr3LossTolerancePct = 5;
//
// Multiplicative decay applied to the recovery window on above-threshold loss,
// as a percentage (70 => x0.70), instead of subtracting all lost bytes.
//
static const uint32_t kBbr3RecoveryDecayPct = 70;
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3BandwidthFilterOnPacketAcked(
    _In_ BBR3_BANDWIDTH_FILTER* b,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t RttCounter
    )
{
    if (b->AppLimited && b->AppLimitedExitTarget < AckEvent->LargestAck) {
        b->AppLimited = FALSE;
    }

    uint64_t TimeNow = AckEvent->TimeNow;

    QUIC_SENT_PACKET_METADATA* AckedPacketsIterator = AckEvent->AckedPackets;
    while (AckedPacketsIterator != NULL) {
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckedPacketsIterator;
        AckedPacketsIterator = AckedPacketsIterator->Next;

        if (AckedPacket->PacketLength == 0) {
            continue;
        }

        uint64_t SendRate = UINT64_MAX;
        uint64_t AckRate = UINT64_MAX;

        if (AckedPacket->Flags.HasLastAckedPacketInfo) {
            CXPLAT_DBG_ASSERT(AckedPacket->TotalBytesSent >= AckedPacket->LastAckedPacketInfo.TotalBytesSent);
            CXPLAT_DBG_ASSERT(CxPlatTimeAtOrBefore64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime));

            uint64_t AckElapsed = 0;
            uint64_t SendElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime);

            if (SendElapsed) {
                SendRate = (kMicroSecsInSec * BW_UNIT *
                    (AckedPacket->TotalBytesSent - AckedPacket->LastAckedPacketInfo.TotalBytesSent) /
                    SendElapsed);
            }

            if (!CxPlatTimeAtOrBefore64(AckEvent->AdjustedAckTime, AckedPacket->LastAckedPacketInfo.AdjustedAckTime)) {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AckTime, TimeNow);
            }

            CXPLAT_DBG_ASSERT(AckEvent->NumTotalAckedRetransmittableBytes >= AckedPacket->LastAckedPacketInfo.TotalBytesAcked);
            if (AckElapsed) {
                AckRate = (kMicroSecsInSec * BW_UNIT *
                           (AckEvent->NumTotalAckedRetransmittableBytes - AckedPacket->LastAckedPacketInfo.TotalBytesAcked) /
                           AckElapsed);
            }
        } else if (!CxPlatTimeAtOrBefore64(TimeNow, AckedPacket->SentTime)) {
            CXPLAT_DBG_ASSERT(CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow) != 0);
            SendRate = (kMicroSecsInSec * BW_UNIT *
                        AckEvent->NumTotalAckedRetransmittableBytes /
                        CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow));
        }

        if (SendRate == UINT64_MAX && AckRate == UINT64_MAX) {
            continue;
        }

        uint64_t DeliveryRate = CXPLAT_MIN(SendRate, AckRate);

        QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
        QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&b->WindowedMaxFilter, &Entry);

        uint64_t PreviousMaxDeliveryRate = 0;
        if (QUIC_SUCCEEDED(Status)) {
            PreviousMaxDeliveryRate = Entry.Value;
        }

        if (DeliveryRate >= PreviousMaxDeliveryRate || !AckedPacket->Flags.IsAppLimited) {
            QuicSlidingWindowExtremumUpdateMax(&b->WindowedMaxFilter, DeliveryRate, RttCounter);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3CongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Cc->Bbr3.BandwidthFilter.WindowedMaxFilter, &Entry);
    if (QUIC_SUCCEEDED(Status)) {
        return Entry.Value;
    }
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlInRecovery(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
)
{
    return Cc->Bbr3.RecoveryState != RECOVERY_STATE_NOT_RECOVERY;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3CongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (Bbr3->BbrState == BBR_STATE_PROBE_RTT) {
        return MinCongestionWindow;
    }

    if (Bbr3CongestionControlInRecovery(Cc)) {
        return CXPLAT_MIN(Bbr3->CongestionWindow, Bbr3->RecoveryWindow);
    }

    return Bbr3->CongestionWindow;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlTransitToProbeBw(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t CongestionEventTime
    )
{
    QUIC_CONGESTION_CONTROL_BBR3 *Bbr3 = &Cc->Bbr3;

    Bbr3->BbrState = BBR_STATE_PROBE_BW;
    Bbr3->CwndGain = kCwndGain;

    uint32_t RandomValue = 0;
    CxPlatRandom(sizeof(uint32_t), &RandomValue);
    Bbr3->PacingCycleIndex = (RandomValue % (GAIN_CYCLE_LENGTH - 1) + 2) % GAIN_CYCLE_LENGTH;
    CXPLAT_DBG_ASSERT(Bbr3->PacingCycleIndex != 1);
    Bbr3->PacingGain = kPacingGain[Bbr3->PacingCycleIndex];

    Bbr3->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr3.BbrState = BBR_STATE_STARTUP;
    Cc->Bbr3.PacingGain = kHighGain;
    Cc->Bbr3.CwndGain = kHighGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr3.BandwidthFilter.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnLogBbr3(
    _In_ QUIC_CONNECTION* const Connection
    )
{
    QUIC_CONGESTION_CONTROL* Cc = &Connection->CongestionControl;
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    QuicTraceEvent(
        ConnBbr,
        "[conn][%p] BBR: State=%u RState=%u CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%u",
        Connection,
        Bbr3->BbrState,
        Bbr3->RecoveryState,
        Bbr3CongestionControlGetCongestionWindow(Cc),
        Bbr3->BytesInFlight,
        Bbr3->BytesInFlightMax,
        Bbr3->MinRtt,
        Bbr3CongestionControlGetBandwidth(Cc) / BW_UNIT,
        Bbr3CongestionControlIsAppLimited(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlIndicateConnectionEvent(
    _In_ QUIC_CONNECTION* const Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;
    const QUIC_PATH* Path = &Connection->Paths[0];
    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_NETWORK_STATISTICS;
    Event.NETWORK_STATISTICS.BytesInFlight = Bbr3->BytesInFlight;
    Event.NETWORK_STATISTICS.PostedBytes = Connection->SendBuffer.PostedBytes;
    Event.NETWORK_STATISTICS.IdealBytes = Connection->SendBuffer.IdealBytes;
    Event.NETWORK_STATISTICS.SmoothedRTT = Path->SmoothedRtt;
    Event.NETWORK_STATISTICS.CongestionWindow = Bbr3CongestionControlGetCongestionWindow(Cc);
    Event.NETWORK_STATISTICS.Bandwidth = Bbr3CongestionControlGetBandwidth(Cc) / BW_UNIT;

    QuicTraceLogConnVerbose(
        IndicateDataAcked,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]",
        Event.NETWORK_STATISTICS.BytesInFlight,
        Event.NETWORK_STATISTICS.PostedBytes,
        Event.NETWORK_STATISTICS.IdealBytes,
        Event.NETWORK_STATISTICS.SmoothedRTT,
        Event.NETWORK_STATISTICS.CongestionWindow,
        Event.NETWORK_STATISTICS.Bandwidth);
    QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    uint32_t CongestionWindow = Bbr3CongestionControlGetCongestionWindow(Cc);
    return Cc->Bbr3.BytesInFlight < CongestionWindow || Cc->Bbr3.Exemptions > 0;
}

void
Bbr3CongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    const QUIC_PATH* Path = &Connection->Paths[0];
    const QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    QuicTraceEvent(
        ConnOutFlowStatsV2,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Bbr3->BytesInFlight,
        Bbr3->CongestionWindow,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0,
        Path->OneWayDelay);
}

//
// Returns TRUE if we became unblocked.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicConnLogOutFlowStats(Connection);

    if (PreviousCanSendState != Bbr3CongestionControlCanSend(Cc)) {
        if (PreviousCanSendState) {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_CONGESTION_CONTROL);
        } else {
            QuicConnRemoveOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_CONGESTION_CONTROL);
            Connection->Send.LastFlushTime = CxPlatTimeUs64(); // Reset last flush time
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3CongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr3.BytesInFlightMax;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
Bbr3CongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr3.Exemptions;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->Bbr3.Exemptions = NumPackets;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    BOOLEAN PreviousCanSendState = Bbr3CongestionControlCanSend(Cc);

    if (!Bbr3->BytesInFlight && Bbr3CongestionControlIsAppLimited(Cc)) {
        Bbr3->ExitingQuiescence = TRUE;
    }

    Bbr3->BytesInFlight += NumRetransmittableBytes;
    if (Bbr3->BytesInFlightMax < Bbr3->BytesInFlight) {
        Bbr3->BytesInFlightMax = Bbr3->BytesInFlight;
        QuicSendBufferConnectionAdjust(QuicCongestionControlGetConnection(Cc));
    }

    if (Bbr3->Exemptions > 0) {
        --Bbr3->Exemptions;
    }

    Bbr3CongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    BOOLEAN PreviousCanSendState = Bbr3CongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Bbr3->BytesInFlight >= NumRetransmittableBytes);
    Bbr3->BytesInFlight -= NumRetransmittableBytes;

    return Bbr3CongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlUpdateRecoveryWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t BytesAcked
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    CXPLAT_DBG_ASSERT(Bbr3->RecoveryState != RECOVERY_STATE_NOT_RECOVERY);

    if (Bbr3->RecoveryState == RECOVERY_STATE_GROWTH) {
        Bbr3->RecoveryWindow += BytesAcked;
    }

    uint32_t RecoveryWindow = CXPLAT_MAX(
        Bbr3->RecoveryWindow, Bbr3->BytesInFlight + BytesAcked);

#if BBR_PHASE_A_LOSS_PATCH
    uint32_t MinCongestionWindow =
        CXPLAT_MAX(kMinCwndInMss, kBbr3RecoveryFloorPackets) * DatagramPayloadLength;
#else
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;
#endif

    Bbr3->RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlHandleAckInProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t LargestSentPacketNumber,
    _In_ uint64_t AckTime
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    Bbr3->BandwidthFilter.AppLimited = TRUE;
    Bbr3->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (!Bbr3->ProbeRttEndTimeValid &&
        Bbr3->BytesInFlight < Bbr3CongestionControlGetCongestionWindow(Cc) + DatagramPayloadLength) {

        Bbr3->ProbeRttEndTime = AckTime + kProbeRttTimeInUs;
        Bbr3->ProbeRttEndTimeValid = TRUE;

        Bbr3->ProbeRttRoundValid = FALSE;

        return;
    }

    if (Bbr3->ProbeRttEndTimeValid) {

        if (!Bbr3->ProbeRttRoundValid && NewRoundTrip) {
            Bbr3->ProbeRttRoundValid = TRUE;
            Bbr3->ProbeRttRound = Bbr3->RoundTripCounter;
        }

        if (Bbr3->ProbeRttRoundValid && CxPlatTimeAtOrBefore64(Bbr3->ProbeRttEndTime, AckTime)) {
            Bbr3->MinRttTimestamp = AckTime;
            Bbr3->MinRttTimestampValid = TRUE;

            if (Bbr3->BtlbwFound) {
                Bbr3CongestionControlTransitToProbeBw(Cc, AckTime);
            } else {
                Bbr3CongestionControlTransitToStartup(Cc);
            }
        }

    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3CongestionControlUpdateAckAggregation(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    if (!Bbr3->AckAggregationStartTimeValid) {
        Bbr3->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr3->AckAggregationStartTimeValid = TRUE;
        return 0;
    }

    uint64_t ExpectedAckBytes = Bbr3CongestionControlGetBandwidth(Cc) *
                                CxPlatTimeDiff64(Bbr3->AckAggregationStartTime, AckEvent->TimeNow) /
                                kMicroSecsInSec /
                                BW_UNIT;

    //
    // Reset current ack aggregation status when we witness ack arrival rate being less or equal than
    // estimated bandwidth
    //
    if (Bbr3->AggregatedAckBytes <= ExpectedAckBytes) {
        Bbr3->AggregatedAckBytes = AckEvent->NumRetransmittableBytes;
        Bbr3->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr3->AckAggregationStartTimeValid = TRUE;

        return 0;
    }

    Bbr3->AggregatedAckBytes += AckEvent->NumRetransmittableBytes;

    QuicSlidingWindowExtremumUpdateMax(&Bbr3->MaxAckHeightFilter,
        Bbr3->AggregatedAckBytes - ExpectedAckBytes, Bbr3->RoundTripCounter);

    return Bbr3->AggregatedAckBytes - ExpectedAckBytes;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3CongestionControlGetTargetCwnd(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t Gain
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    uint64_t BandwidthEst = Bbr3CongestionControlGetBandwidth(Cc);

    if (!BandwidthEst || Bbr3->MinRtt == UINT32_MAX) {
        return (uint64_t)(Gain) * Bbr3->InitialCongestionWindow / GAIN_UNIT;
    }

    uint64_t Bdp = BandwidthEst * Bbr3->MinRtt / kMicroSecsInSec / BW_UNIT;
    uint64_t TargetCwnd = (Bdp * Gain / GAIN_UNIT) + (kQuantaFactor * Bbr3->SendQuantum);
    return (uint32_t)TargetCwnd;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3CongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    uint64_t BandwidthEst = Bbr3CongestionControlGetBandwidth(Cc);
    uint32_t CongestionWindow = Bbr3CongestionControlGetCongestionWindow(Cc);

    uint32_t SendAllowance = 0;

    if (Bbr3->BytesInFlight >= CongestionWindow) {
        //
        // We are CC blocked, so we can't send anything.
        //
        SendAllowance = 0;

    } else if (
        !TimeSinceLastSendValid ||
        !Connection->Settings.PacingEnabled ||
        Bbr3->MinRtt == UINT32_MAX ||
        Bbr3->MinRtt < QUIC_SEND_PACING_INTERVAL) {
        //
        // We're not in the necessary state to pace.
        //
        SendAllowance = CongestionWindow - Bbr3->BytesInFlight;

    } else {
        //
        // We are pacing, so split the congestion window into chunks which are
        // spread out over the RTT. Calculate the current send allowance (chunk
        // size) as the time since the last send times the pacing rate (CWND / RTT).
        //
        if (Bbr3->BbrState == BBR_STATE_STARTUP) {
            SendAllowance = (uint32_t)CXPLAT_MAX(
                BandwidthEst * Bbr3->PacingGain * TimeSinceLastSend / GAIN_UNIT,
                CongestionWindow * Bbr3->PacingGain / GAIN_UNIT - Bbr3->BytesInFlight);
        } else {
            SendAllowance = (uint32_t)(BandwidthEst * Bbr3->PacingGain * TimeSinceLastSend / GAIN_UNIT);
        }

        if (SendAllowance > CongestionWindow - Bbr3->BytesInFlight) {
            SendAllowance = CongestionWindow - Bbr3->BytesInFlight;
        }

        if (SendAllowance > (CongestionWindow >> 2)) {
            SendAllowance = CongestionWindow >> 2; // Don't send more than a quarter of the current window.
        }
    }
    return SendAllowance;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    Bbr3->BbrState = BBR_STATE_PROBE_RTT;
    Bbr3->PacingGain = GAIN_UNIT;
    Bbr3->ProbeRttEndTimeValid = FALSE;
    Bbr3->ProbeRttRoundValid = FALSE;

    Bbr3->BandwidthFilter.AppLimited = TRUE;
    Bbr3->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr3.BbrState = BBR_STATE_DRAIN;
    Cc->Bbr3.PacingGain = kDrainGain;
    Cc->Bbr3.CwndGain = kHighGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlSetSendQuantum(
    _In_ QUIC_CONGESTION_CONTROL* Cc
)
{
    QUIC_CONGESTION_CONTROL_BBR3 *Bbr3 = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    uint64_t Bandwidth = Bbr3CongestionControlGetBandwidth(Cc);

    uint64_t PacingRate = Bandwidth * Bbr3->PacingGain / GAIN_UNIT;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (PacingRate < kLowPacingRateThresholdBytesPerSecond * BW_UNIT) {
        Bbr3->SendQuantum = (uint64_t)DatagramPayloadLength;
    } else if (PacingRate < kHighPacingRateThresholdBytesPerSecond * BW_UNIT) {
        Bbr3->SendQuantum = (uint64_t)DatagramPayloadLength * 2;
    } else {
        Bbr3->SendQuantum = CXPLAT_MIN(PacingRate * kMilliSecsInSec / BW_UNIT, 64 * 1024 /* 64k */);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlUpdateCongestionWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR3 *Bbr3 = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (Bbr3->BbrState == BBR_STATE_PROBE_RTT) {
        return;
    }

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr3CongestionControlSetSendQuantum(Cc);

    uint64_t TargetCwnd = Bbr3CongestionControlGetTargetCwnd(Cc, Bbr3->CwndGain);
    if (Bbr3->BtlbwFound) {
        QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
        QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Bbr3->MaxAckHeightFilter, &Entry);
        if (QUIC_SUCCEEDED(Status)) {
            TargetCwnd += Entry.Value;
        }
    }

    uint32_t CongestionWindow = Bbr3->CongestionWindow;
#if BBR_PHASE_A_LOSS_PATCH
    //
    // Phase A.5: floor the congestion window itself, not just the recovery
    // window. GetCongestionWindow returns min(CongestionWindow, RecoveryWindow)
    // while in recovery, so a CongestionWindow that collapses to kMinCwndInMss
    // (when the bandwidth estimate drops during a loss burst) would otherwise
    // nullify the higher recovery-window floor and pin the effective cwnd at
    // 4*MSS.
    //
    uint32_t MinCongestionWindow =
        CXPLAT_MAX(kMinCwndInMss, kBbr3RecoveryFloorPackets) * DatagramPayloadLength;
#else
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;
#endif

    if (Bbr3->BtlbwFound) {
        CongestionWindow = (uint32_t)CXPLAT_MIN(TargetCwnd, CongestionWindow + AckedBytes);
    } else if (CongestionWindow < TargetCwnd || TotalBytesAcked < Bbr3->InitialCongestionWindow) {
        CongestionWindow += (uint32_t)AckedBytes;
    }

    Bbr3->CongestionWindow = CXPLAT_MAX(CongestionWindow, MinCongestionWindow);

    QuicConnLogBbr3(QuicCongestionControlGetConnection(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    BOOLEAN PreviousCanSendState = Bbr3CongestionControlCanSend(Cc);
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (AckEvent->IsImplicit) {
        Bbr3CongestionControlUpdateCongestionWindow(
            Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

        if (Connection->Settings.NetStatsEventEnabled) {
            Bbr3CongestionControlIndicateConnectionEvent(Connection, Cc);
        }
        return Bbr3CongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    }

    uint32_t PrevInflightBytes = Bbr3->BytesInFlight;

    CXPLAT_DBG_ASSERT(Bbr3->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr3->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    if (AckEvent->MinRttValid) {
        Bbr3->RttSampleExpired = Bbr3->MinRttTimestampValid ?
           CxPlatTimeAtOrBefore64(Bbr3->MinRttTimestamp + kBbr3MinRttExpirationInMicroSecs, AckEvent->TimeNow) :
           FALSE;
        if (Bbr3->RttSampleExpired || Bbr3->MinRtt > AckEvent->MinRtt) {
            Bbr3->MinRtt = AckEvent->MinRtt;
            Bbr3->MinRttTimestamp = AckEvent->TimeNow;
            Bbr3->MinRttTimestampValid = TRUE;
        }
    }

    BOOLEAN NewRoundTrip = FALSE;
    if (!Bbr3->EndOfRoundTripValid || Bbr3->EndOfRoundTrip < AckEvent->LargestAck) {
        Bbr3->RoundTripCounter++;
        Bbr3->EndOfRoundTripValid = TRUE;
        Bbr3->EndOfRoundTrip = AckEvent->LargestSentPacketNumber;
        NewRoundTrip = TRUE;
    }

    BOOLEAN LastAckedPacketAppLimited =
        AckEvent->AckedPackets == NULL ? FALSE : AckEvent->IsLargestAckedPacketAppLimited;

    Bbr3BandwidthFilterOnPacketAcked(&Bbr3->BandwidthFilter, AckEvent, Bbr3->RoundTripCounter);

    if (Bbr3CongestionControlInRecovery(Cc)) {
        CXPLAT_DBG_ASSERT(Bbr3->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr3->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr3->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (!AckEvent->HasLoss && Bbr3->EndOfRecovery < AckEvent->LargestAck) {
            Bbr3->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
            QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
        } else {
            Bbr3CongestionControlUpdateRecoveryWindow(Cc, AckEvent->NumRetransmittableBytes);
        }
    }

    Bbr3CongestionControlUpdateAckAggregation(Cc, AckEvent);

    if (Bbr3->BbrState == BBR_STATE_PROBE_BW) {
        BOOLEAN ShouldAdvancePacingGainCycle = CxPlatTimeDiff64(AckEvent->TimeNow, Bbr3->CycleStart) > Bbr3->MinRtt;

        if (Bbr3->PacingGain > GAIN_UNIT && !AckEvent->HasLoss &&
            PrevInflightBytes < Bbr3CongestionControlGetTargetCwnd(Cc, Bbr3->PacingGain)) {
            ShouldAdvancePacingGainCycle = FALSE;
        }

        if (Bbr3->PacingGain < GAIN_UNIT) {
            uint64_t TargetCwnd = Bbr3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT);
            if (Bbr3->BytesInFlight <= TargetCwnd) {
                ShouldAdvancePacingGainCycle = TRUE;
            }
        }

        if (ShouldAdvancePacingGainCycle) {
            Bbr3->PacingCycleIndex = (Bbr3->PacingCycleIndex + 1) % GAIN_CYCLE_LENGTH;
            Bbr3->CycleStart = AckEvent->TimeNow;
            Bbr3->PacingGain = kPacingGain[Bbr3->PacingCycleIndex];
        }
    }

    if (!Bbr3->BtlbwFound && NewRoundTrip && !LastAckedPacketAppLimited) {
        uint64_t BandwidthTarget = (uint64_t)(Bbr3->LastEstimatedStartupBandwidth * kStartupGrowthTarget / GAIN_UNIT);
        uint64_t CurrentBandwidth = Bbr3CongestionControlGetBandwidth(Cc);

        if (CurrentBandwidth >= BandwidthTarget) {
            Bbr3->LastEstimatedStartupBandwidth = CurrentBandwidth;
            Bbr3->SlowStartupRoundCounter = 0;
        } else if (++Bbr3->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
            Bbr3->BtlbwFound = TRUE;
        }
    }

    if (Bbr3->BbrState == BBR_STATE_STARTUP && Bbr3->BtlbwFound) {
        Bbr3CongestionControlTransitToDrain(Cc);
    }

    if (Bbr3->BbrState == BBR_STATE_DRAIN &&
           Bbr3->BytesInFlight <= Bbr3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT)) {
        Bbr3CongestionControlTransitToProbeBw(Cc, AckEvent->TimeNow);
    }

    if (Bbr3->BbrState != BBR_STATE_PROBE_RTT &&
        !Bbr3->ExitingQuiescence &&
        Bbr3->RttSampleExpired) {
        Bbr3CongestionControlTransitToProbeRtt(Cc, AckEvent->LargestSentPacketNumber);
    }

    Bbr3->ExitingQuiescence = FALSE;

    if (Bbr3->BbrState == BBR_STATE_PROBE_RTT) {
        Bbr3CongestionControlHandleAckInProbeRtt(
            Cc, NewRoundTrip, AckEvent->LargestSentPacketNumber, AckEvent->TimeNow);
    }

    Bbr3CongestionControlUpdateCongestionWindow(
        Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

    if (Connection->Settings.NetStatsEventEnabled) {
        Bbr3CongestionControlIndicateConnectionEvent(Connection, Cc);
    }

    return Bbr3CongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR3 *Bbr3 = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    QuicTraceEvent(
        ConnCongestionV2,
        "[conn][%p] Congestion event: IsEcn=%hu",
        Connection,
        FALSE);
    Connection->Stats.Send.CongestionCount++;

    BOOLEAN PreviousCanSendState = Bbr3CongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(LossEvent->NumRetransmittableBytes > 0);

    Bbr3->EndOfRecoveryValid = TRUE;
    Bbr3->EndOfRecovery = LossEvent->LargestSentPacketNumber;

    CXPLAT_DBG_ASSERT(Bbr3->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr3->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    uint32_t RecoveryWindow = Bbr3->RecoveryWindow;
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (!Bbr3CongestionControlInRecovery(Cc)) {
        Bbr3->RecoveryState = RECOVERY_STATE_CONSERVATIVE;
        RecoveryWindow = Bbr3->BytesInFlight;

        RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);

        Bbr3->EndOfRoundTripValid = TRUE;
        Bbr3->EndOfRoundTrip = LossEvent->LargestSentPacketNumber;
    }

    if (LossEvent->PersistentCongestion) {
#if BBR_PHASE_A_LOSS_PATCH
        //
        // Phase A.5: keep persistent-congestion recovery at the higher floor
        // too; dropping straight to kMinCwndInMss here also bypasses Phase A.
        //
        Bbr3->RecoveryWindow =
            CXPLAT_MAX(MinCongestionWindow, kBbr3RecoveryFloorPackets * DatagramPayloadLength);
#else
        Bbr3->RecoveryWindow = MinCongestionWindow;
#endif

        QuicTraceEvent(
            ConnPersistentCongestion,
            "[conn][%p] Persistent congestion event",
            Connection);
        Connection->Stats.Send.PersistentCongestionCount++;
    } else {
#if BBR_PHASE_A_LOSS_PATCH
        //
        // Recovery-window floor for the loss path (>= MinCongestionWindow).
        //
        uint32_t RecoveryFloor =
            CXPLAT_MAX(MinCongestionWindow, kBbr3RecoveryFloorPackets * DatagramPayloadLength);
        //
        // Pre-loss bytes-in-flight. BytesInFlight was already decremented above by
        // LossEvent->NumRetransmittableBytes, so add it back to get the denominator.
        //
        uint64_t PreLossInFlight =
            (uint64_t)Bbr3->BytesInFlight + LossEvent->NumRetransmittableBytes;
        if (PreLossInFlight != 0 &&
            (uint64_t)LossEvent->NumRetransmittableBytes * 100 <
                (uint64_t)kBbr3LossTolerancePct * PreLossInFlight) {
            //
            // Sub-threshold (random) loss: do not shrink the window, only floor it.
            //
            Bbr3->RecoveryWindow = CXPLAT_MAX(RecoveryWindow, RecoveryFloor);
        } else {
            //
            // Above-threshold loss: gentle multiplicative decay instead of
            // subtracting every lost byte (which is what collapses the window).
            //
            uint32_t DecayedWindow =
                (uint32_t)((uint64_t)RecoveryWindow * kBbr3RecoveryDecayPct / 100);
            Bbr3->RecoveryWindow = CXPLAT_MAX(DecayedWindow, RecoveryFloor);
        }
#else
        Bbr3->RecoveryWindow =
            RecoveryWindow > LossEvent->NumRetransmittableBytes + MinCongestionWindow
            ? RecoveryWindow - LossEvent->NumRetransmittableBytes
            : MinCongestionWindow;
#endif
    }

    Bbr3CongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    QuicConnLogBbr3(QuicCongestionControlGetConnection(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    UNREFERENCED_PARAMETER(Cc);
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlSetAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3 *Bbr3 = &Cc->Bbr3;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    uint64_t LargestSentPacketNumber = Connection->LossDetection.LargestSentPacketNumber;

    if (Bbr3->BytesInFlight > Bbr3CongestionControlGetCongestionWindow(Cc)) {
        return;
    }

    Bbr3->BandwidthFilter.AppLimited = TRUE;
    Bbr3->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr3->CongestionWindow = Bbr3->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr3->InitialCongestionWindow = Bbr3->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr3->RecoveryWindow = kDefaultRecoveryCwndInMss * DatagramPayloadLength;
    Bbr3->BytesInFlightMax = Bbr3->CongestionWindow / 2;

    if (FullReset) {
        Bbr3->BytesInFlight = 0;
    }
    Bbr3->Exemptions = 0;

    Bbr3->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr3->BbrState = BBR_STATE_STARTUP;
    Bbr3->RoundTripCounter = 0;
    Bbr3->CwndGain = kHighGain;
    Bbr3->PacingGain = kHighGain;
    Bbr3->BtlbwFound = FALSE;
    Bbr3->SendQuantum = 0;
    Bbr3->SlowStartupRoundCounter = 0 ;

    Bbr3->PacingCycleIndex = 0;
    Bbr3->AggregatedAckBytes = 0;
    Bbr3->ExitingQuiescence = FALSE;
    Bbr3->LastEstimatedStartupBandwidth = 0;

    Bbr3->AckAggregationStartTimeValid = FALSE;
    Bbr3->AckAggregationStartTime = CxPlatTimeUs64();
    Bbr3->CycleStart = 0;

    Bbr3->EndOfRecoveryValid = FALSE;
    Bbr3->EndOfRecovery = 0;

    Bbr3->ProbeRttRoundValid = FALSE;
    Bbr3->ProbeRttRound = 0;

    Bbr3->EndOfRoundTripValid = FALSE;
    Bbr3->EndOfRoundTrip = 0;

    Bbr3->ProbeRttEndTimeValid = FALSE;
    Bbr3->ProbeRttEndTime = CxPlatTimeUs64();

    Bbr3->RttSampleExpired = TRUE;
    Bbr3->MinRttTimestampValid = FALSE;
    Bbr3->MinRtt = UINT64_MAX;
    Bbr3->MinRttTimestamp = 0;

    QuicSlidingWindowExtremumReset(&Bbr3->MaxAckHeightFilter);

    QuicSlidingWindowExtremumReset(&Bbr3->BandwidthFilter.WindowedMaxFilter);
    Bbr3->BandwidthFilter.AppLimited = FALSE;
    Bbr3->BandwidthFilter.AppLimitedExitTarget = 0;

    Bbr3CongestionControlLogOutFlowStatus(Cc);
    QuicConnLogBbr3(Connection);
}


static const QUIC_CONGESTION_CONTROL QuicCongestionControlBbr3 = {
    .Name = "BBR",
    .QuicCongestionControlCanSend = Bbr3CongestionControlCanSend,
    .QuicCongestionControlSetExemption = Bbr3CongestionControlSetExemption,
    .QuicCongestionControlReset = Bbr3CongestionControlReset,
    .QuicCongestionControlGetSendAllowance = Bbr3CongestionControlGetSendAllowance,
    .QuicCongestionControlGetCongestionWindow = Bbr3CongestionControlGetCongestionWindow,
    .QuicCongestionControlOnDataSent = Bbr3CongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = Bbr3CongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = Bbr3CongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = Bbr3CongestionControlOnDataLost,
    .QuicCongestionControlOnEcn = NULL,
    .QuicCongestionControlOnSpuriousCongestionEvent = Bbr3CongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = Bbr3CongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = Bbr3CongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = Bbr3CongestionControlGetBytesInFlightMax,
    .QuicCongestionControlIsAppLimited = Bbr3CongestionControlIsAppLimited,
    .QuicCongestionControlSetAppLimited = Bbr3CongestionControlSetAppLimited,
};

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    *Cc = QuicCongestionControlBbr3;

    QUIC_CONGESTION_CONTROL_BBR3* Bbr3 = &Cc->Bbr3;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr3->InitialCongestionWindowPackets = Settings->InitialWindowPackets;

    Bbr3->CongestionWindow = Bbr3->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr3->InitialCongestionWindow = Bbr3->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr3->RecoveryWindow = kDefaultRecoveryCwndInMss * DatagramPayloadLength;
    Bbr3->BytesInFlightMax = Bbr3->CongestionWindow / 2;

    Bbr3->BytesInFlight = 0;
    Bbr3->Exemptions = 0;

    Bbr3->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr3->BbrState = BBR_STATE_STARTUP;
    Bbr3->RoundTripCounter = 0;
    Bbr3->CwndGain = kHighGain;
    Bbr3->PacingGain = kHighGain;
    Bbr3->BtlbwFound = FALSE;
    Bbr3->SendQuantum = 0;
    Bbr3->SlowStartupRoundCounter = 0 ;

    Bbr3->PacingCycleIndex = 0;
    Bbr3->AggregatedAckBytes = 0;
    Bbr3->ExitingQuiescence = FALSE;
    Bbr3->LastEstimatedStartupBandwidth = 0;
    Bbr3->CycleStart = 0;

    Bbr3->AckAggregationStartTimeValid = FALSE;
    Bbr3->AckAggregationStartTime = CxPlatTimeUs64();

    Bbr3->EndOfRecoveryValid = FALSE;
    Bbr3->EndOfRecovery = 0;

    Bbr3->ProbeRttRoundValid = FALSE;
    Bbr3->ProbeRttRound = 0;

    Bbr3->EndOfRoundTripValid = FALSE;
    Bbr3->EndOfRoundTrip = 0;

    Bbr3->ProbeRttEndTimeValid = FALSE;
    Bbr3->ProbeRttEndTime = 0;

    Bbr3->RttSampleExpired = TRUE;
    Bbr3->MinRttTimestampValid = FALSE;
    Bbr3->MinRtt = UINT64_MAX;
    Bbr3->MinRttTimestamp = 0;

    Bbr3->MaxAckHeightFilter = QuicSlidingWindowExtremumInitialize(
            kBbr3MaxAckHeightFilterLen, kBbr3DefaultFilterCapacity, Bbr3->MaxAckHeightFilterEntries);

    Bbr3->BandwidthFilter = (BBR3_BANDWIDTH_FILTER) {
        .WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(
                kBbr3MaxBandwidthFilterLen, kBbr3DefaultFilterCapacity, Bbr3->BandwidthFilter.WindowedMaxFilterEntries),
        .AppLimited = FALSE,
        .AppLimitedExitTarget = 0,
    };

    QuicConnLogOutFlowStats(Connection);
    QuicConnLogBbr3(Connection);
}
