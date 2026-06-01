/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    BBRv3 congestion control. A pure-C port of Google QUICHE's bbr2_* sender
    (which implements BBRv3 under default parameters), adapted to msquic's
    aggregate ACK/loss event model.

    Design notes:
      * Integer fixed-point only (GAIN_UNIT/BW_UNIT), no floating point, so this
        file also compiles for the Windows kernel driver.
      * Bandwidth is stored as (bytes/sec * BW_UNIT), matching the delivery-rate
        sampler reused from msquic's BBRv1.
      * Only the default-parameter code path is ported; experimental
        connection-option branches in QUICHE are omitted.
      * msquic delivers loss (OnDataLost) and acks (OnDataAcknowledged)
        separately, loss first. We buffer loss and flush it together with the
        next ack to form a single quic::Bbr2CongestionEvent.

    Reference: quiche/quic/core/congestion_control/bbr2_*.{h,cc}

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "bbr3.c.clog.h"
#endif

//
// Debugging instrumentation: file tracing. DISABLED -- synchronous file I/O from
// the CC callbacks (many worker threads, one file) was the source of the
// serverTest crash (ntdll AV). To re-enable for a controlled debug run, define
// BBR3_FILE_TRACE=1 and add `#include <stdio.h>` here.
//
// #define BBR3_FILE_TRACE 1

//
// Bandwidth is measured as (bytes / BW_UNIT) per second.
//
#define BW_UNIT 8

//
// Gain is measured as (1 / GAIN_UNIT).
//
#define GAIN_UNIT 256

#define kMicroSecsInSec 1000000ULL

#define BBR3_INFINITE_BANDWIDTH UINT64_MAX
#define BBR3_INFINITE_INFLIGHT  UINT64_MAX

//
// cwnd_limits.Min(): kDefaultMinimumCongestionWindow = 4 * MSS.
//
static const uint32_t kBbr3MinCwndInMss = 4;

//
// Gains as fixed-point multiples of (1 / GAIN_UNIT).
//
static const uint32_t kBbr3StartupPacingGain = 739; // 2.885
static const uint32_t kBbr3StartupCwndGain = 512;   // 2.0
static const uint32_t kBbr3DrainPacingGain = 89;    // 1 / 2.885
static const uint32_t kBbr3DrainCwndGain = 512;     // 2.0
static const uint32_t kBbr3ProbeBwUpPacingGain = 320;   // 1.25
static const uint32_t kBbr3ProbeBwDownPacingGain = 233; // 0.91
static const uint32_t kBbr3ProbeBwDefaultPacingGain = 256; // 1.0
static const uint32_t kBbr3ProbeBwCwndGain = 512;   // 2.0

//
// full_bw_threshold = 1.25, expressed as a fraction (num / den).
//
static const uint32_t kBbr3FullBwThresholdNum = 5;
static const uint32_t kBbr3FullBwThresholdDen = 4;

//
// (1 - beta) with beta = 0.3, expressed as a fraction (num / den).
//
static const uint32_t kBbr3OneMinusBetaNum = 7;
static const uint32_t kBbr3OneMinusBetaDen = 10;

//
// inflight_hi_headroom = 0.15, expressed as a fraction (num / den).
//
static const uint32_t kBbr3InflightHiHeadroomNum = 15;
static const uint32_t kBbr3InflightHiHeadroomDen = 100;

//
// loss_threshold = 0.02 (2%). Compared as: bytes_lost * 100 > inflight * pct.
//
static const uint32_t kBbr3LossThresholdPct = 2;

static const uint64_t kBbr3StartupFullBwRounds = 3;
static const int64_t kBbr3StartupFullLossCount = 8;
static const int64_t kBbr3ProbeBwFullLossCount = 2;

static const uint64_t kBbr3ProbeBwProbeBaseDurationUs = 2000 * 1000;     // 2s
static const uint64_t kBbr3ProbeBwProbeMaxRandDurationUs = 1000 * 1000;  // 1s
static const uint64_t kBbr3ProbeBwMaxProbeRandRounds = 2;
static const uint64_t kBbr3ProbeBwProbeMaxRounds = 63;

static const uint64_t kBbr3ProbeRttPeriodUs = 10 * 1000 * 1000; // 10s
static const uint64_t kBbr3ProbeRttDurationUs = 200 * 1000;     // 200ms
//
// probe_rtt_inflight_target_bdp_fraction = 0.5 (num / den).
//
static const uint32_t kBbr3ProbeRttInflightFractionNum = 1;
static const uint32_t kBbr3ProbeRttInflightFractionDen = 2;

static const uint32_t kBbr3MaxAckHeightFilterLen = 10;
static const int kBbr3MaxModeChangesPerCongestionEvent = 4;

//
// Bandwidth-sampler overestimate avoidance (quic BSAO). When enabled, the
// ack-rate sample's A0 baseline is anchored to an earlier ack-aggregation-epoch
// boundary instead of "the most recent ack at the time the packet was sent", so
// that a burst of aggregated acks cannot inflate the delivery-rate sample (and
// thus the 2-slot max-bandwidth filter, the BDP, the cwnd and the pacing rate).
// This is the primary defense against bufferbloat on deep-buffer / ack-
// aggregating links. Set to 0 to fall back to the plain baseline (this is the
// QUICHE default-off behavior, matching msquic's BBRv1 sampler).
//
#ifndef BBR3_OVERESTIMATE_AVOIDANCE
#define BBR3_OVERESTIMATE_AVOIDANCE 1
#endif

//
// rtt-gating for overestimate avoidance. OE de-spikes the bandwidth sample,
// which is correct when a standing queue is inflating the ack rate (bad link),
// but harmful on a clean/fast path where the high samples are the real rate
// (it throttled LAN throughput ~3x in testing). So OE only engages when the
// smoothed rtt is inflated above the min rtt by this fraction (5/4 = +25%),
// i.e. a sustained queue, AND we are past STARTUP (STARTUP's probe must stay
// aggressive to discover bandwidth). On a clean path (rtt ~= minRtt) OE stays
// dormant and bbr3 tracks the real rate like BBR V1.
//
#if BBR3_OVERESTIMATE_AVOIDANCE
static const uint32_t kBbr3OeQueueRttThreshNum = 5;
static const uint32_t kBbr3OeQueueRttThreshDen = 4;
//
// Absolute queue-delay floor for activating OE: in addition to the ratio above,
// the standing queue (SmoothedRtt - MinRtt) must exceed this many microseconds.
// On very-low-rtt paths (loopback/LAN, MinRtt ~ tens-of-us) the ratio alone
// trips on sub-millisecond jitter that is not a real queue, which needlessly
// throttled loopback throughput; this floor keeps OE fully dormant there.
//
static const uint64_t kBbr3OeQueueDelayFloorUs = 2000; // 2 ms
#endif

//
// Restart-from-idle. On a bad link with "dead windows" (stretches of near-100%
// loss in one direction), delivery stalls completely: no acks arrive for
// seconds. When the link recovers, the loss-decayed bandwidth/inflight bounds
// are still pinned low, so plain BBR crawls back up through a full PROBE_BW
// cycle (seconds) instead of re-probing quickly -- which is why an application
// reconnect (a fresh STARTUP) visibly "restores speed" faster than waiting. To
// recover without a reconnect, when an ack arrives after a delivery stall longer
// than the threshold below, BBR re-enters STARTUP (lifting the stale bounds and
// restoring the aggressive gains) so it re-ramps in a few RTTs. This only fires
// after a multi-RTT / sub-second-plus gap with no acks, which never happens
// during a healthy bulk transfer, so steady-state LAN behaviour is unchanged.
// Set to 0 to fall back to plain PROBE_BW recovery.
//
#ifndef BBR3_RESTART_FROM_IDLE
#define BBR3_RESTART_FROM_IDLE 1
#endif

#if BBR3_RESTART_FROM_IDLE
//
// A delivery stall is declared when the gap since the previous ack exceeds
// max(floor, multiple * SmoothedRtt). The RTT multiple keeps it from tripping on
// normal per-RTT ack spacing on high-rtt paths; the absolute floor keeps it from
// tripping on ordinary sub-second app/scheduler jitter on low-rtt paths.
//
static const uint64_t kBbr3RestartIdleFloorUs = 1000000; // 1 s
static const uint32_t kBbr3RestartIdleRttMultiple = 4;
#endif

//
// ---------------------------------------------------------------------------
// The congestion event passed between the model and the modes
// (quic::Bbr2CongestionEvent). Built once per OnDataAcknowledged.
// ---------------------------------------------------------------------------
//
typedef struct BBR3_CONGESTION_EVENT {
    uint64_t EventTime;            // microseconds
    uint32_t PriorCwnd;
    uint64_t PriorBytesInFlight;
    uint64_t BytesInFlight;        // after processing acks+losses
    uint64_t BytesAcked;
    uint64_t BytesLost;
    BOOLEAN EndOfRoundTrip;
    BOOLEAN IsProbingForBandwidth;
    uint64_t SampleMinRtt;         // microseconds, UINT64_MAX if none
    uint64_t SampleMaxBandwidth;   // BW_UNIT-scaled, 0 if none
    BOOLEAN SampleIsAppLimited;    // app-limited flag of the max-bw packet

    //
    // Send-state of the largest acked packet.
    //
    BOOLEAN LastSendStateValid;
    BOOLEAN LastSendStateAppLimited;
    uint64_t LastSendStateInflight;
    uint64_t LastSendStateTotalBytesAcked;
} BBR3_CONGESTION_EVENT;

//
// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------
//

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
Bbr3DatagramPayloadLength(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    return QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);
}

//
// quic::Bbr2MaxBandwidthFilter::Get() == max of the two slots.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3MaxBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    return CXPLAT_MAX(Bbr->MaxBandwidth[0], Bbr->MaxBandwidth[1]);
}

//
// quic::Bbr2NetworkModel::BandwidthEstimate() == min(MaxBandwidth, bandwidth_lo).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3BandwidthEstimate(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    return CXPLAT_MIN(Bbr3MaxBandwidth(Bbr), Bbr->BandwidthLo);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3MaxBandwidthFilterUpdate(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t Sample
    )
{
    if (Sample > Bbr->MaxBandwidth[1]) {
        Bbr->MaxBandwidth[1] = Sample;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3MaxBandwidthFilterAdvance(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    if (Bbr->MaxBandwidth[1] == 0) {
        return;
    }
    Bbr->MaxBandwidth[0] = Bbr->MaxBandwidth[1];
    Bbr->MaxBandwidth[1] = 0;
}

//
// BDP in bytes for a given (BW_UNIT-scaled) bandwidth.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3Bdp(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t BandwidthScaled
    )
{
    if (!Bbr->MinRttTimestampValid || Bbr->MinRtt == 0 || Bbr->MinRtt == UINT64_MAX) {
        return 0;
    }
    return BandwidthScaled * Bbr->MinRtt / kMicroSecsInSec / BW_UNIT;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3BdpWithGain(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t BandwidthScaled,
    _In_ uint32_t GainFp
    )
{
    return Bbr3Bdp(Bbr, BandwidthScaled) * GainFp / GAIN_UNIT;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3GetMinimumCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    return Bbr->MinimumCongestionWindow;
}

//
// quic::Bbr2NetworkModel::inflight_hi_with_headroom().
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3InflightHiWithHeadroom(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    if (Bbr->InflightHi == BBR3_INFINITE_INFLIGHT) {
        return BBR3_INFINITE_INFLIGHT;
    }
    uint64_t Headroom =
        Bbr->InflightHi * kBbr3InflightHiHeadroomNum / kBbr3InflightHiHeadroomDen;
    return Bbr->InflightHi > Headroom ? Bbr->InflightHi - Headroom : 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3MaxAckHeight(
    _In_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status =
        QuicSlidingWindowExtremumGet(&Bbr->MaxAckHeightFilter, &Entry);
    if (QUIC_SUCCEEDED(Status)) {
        return Entry.Value;
    }
    return 0;
}

//
// quic::Bbr2NetworkModel::QueueingThresholdExtraBytes() == 2 * MSS.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3QueueingThresholdExtraBytes(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return 2 * (uint64_t)Bbr3DatagramPayloadLength(Cc);
}

//
// Debugging instrumentation: logs the BBRv3 state at mode/phase transitions.
// Emitted at Info level so the host application's msquic log capture shows it.
// (Bandwidth/pacing are reported in bytes/sec, un-scaled from BW_UNIT.)
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3LogState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_z_ const char* Reason
    )
{
#if BBR3_FILE_TRACE
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    uint64_t BwEst = Bbr3BandwidthEstimate(Bbr);
    if (BwEst == BBR3_INFINITE_BANDWIDTH) {
        BwEst = Bbr3MaxBandwidth(Bbr);
    }
    char Path[96];
    (void)sprintf_s(
        Path, sizeof(Path),
        "D:\\mdidis_test\\log\\bbr3_%lu.log", (unsigned long)GetCurrentProcessId());
    FILE* File = NULL;
    if (fopen_s(&File, Path, "a") == 0 && File != NULL) {
        (void)fprintf(
            File,
            "t=%llu conn=%p %s mode=%u phase=%u cwnd=%u inflight=%u bwBps=%llu "
            "minRttUs=%llu pacingBps=%llu hi=%llu lo=%llu fullBw=%u\n",
            (unsigned long long)CxPlatTimeUs64(),
            (void*)Connection,
            Reason,
            (uint32_t)Bbr->BbrMode,
            (uint32_t)Bbr->ProbePhase,
            Bbr->CongestionWindow,
            Bbr->BytesInFlight,
            (unsigned long long)(BwEst / BW_UNIT),
            (unsigned long long)(Bbr->MinRtt == UINT64_MAX ? 0 : Bbr->MinRtt),
            (unsigned long long)(Bbr->PacingRate / BW_UNIT),
            (unsigned long long)(Bbr->InflightHi == BBR3_INFINITE_INFLIGHT ? 0 : Bbr->InflightHi),
            (unsigned long long)(Bbr->InflightLo == BBR3_INFINITE_INFLIGHT ? 0 : Bbr->InflightLo),
            (uint32_t)Bbr->FullBandwidthReached);
        (void)fclose(File);
    }
#else
    UNREFERENCED_PARAMETER(Cc);
    UNREFERENCED_PARAMETER(Reason);
#endif
}

//
// ---------------------------------------------------------------------------
// Forward declarations.
// ---------------------------------------------------------------------------
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3CongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3GetTargetBytesInflight(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3IsInflightTooHigh(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ const BBR3_CONGESTION_EVENT* Event,
    _In_ int64_t MaxLossEvents
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeDown(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN ProbedTooHigh,
    _In_ BOOLEAN StoppedRiskyProbe,
    _In_ uint64_t Now
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeCruise(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t Now
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeRefill(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t ProbeUpRounds,
    _In_ uint64_t Now
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeUp(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t Now
    );

//
// ---------------------------------------------------------------------------
// Round-trip counter (quic::RoundTripCounter).
// ---------------------------------------------------------------------------
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RoundCounterOnPacketSent(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t PacketNumber
    )
{
    Bbr->LastSentPacketNumber = PacketNumber;
    Bbr->LastSentPacketValid = TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3RoundCounterOnPacketsAcked(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t LastAckedPacket
    )
{
    if (!Bbr->EndOfRoundTripValid || LastAckedPacket > Bbr->EndOfRoundTrip) {
        Bbr->RoundTripCount++;
        Bbr->EndOfRoundTrip = Bbr->LastSentPacketNumber;
        Bbr->EndOfRoundTripValid = TRUE;
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RoundCounterRestartRound(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    Bbr->EndOfRoundTrip = Bbr->LastSentPacketNumber;
    Bbr->EndOfRoundTripValid = TRUE;
}

//
// ---------------------------------------------------------------------------
// Network model (quic::Bbr2NetworkModel).
// ---------------------------------------------------------------------------
//

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3OnNewRound(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    Bbr->BytesLostInRound = 0;
    Bbr->LossEventsInRound = 0;
    Bbr->MaxBytesDeliveredInRound = 0;
    Bbr->MinBytesInFlightInRound = UINT64_MAX;
    Bbr->InflightHiLimitedInRound = FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RestartRoundEarly(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    Bbr3OnNewRound(Bbr);
    Bbr3RoundCounterRestartRound(Bbr);
}

//
// quic::Bbr2NetworkModel::IsInflightTooHigh().
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3IsInflightTooHigh(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ const BBR3_CONGESTION_EVENT* Event,
    _In_ int64_t MaxLossEvents
    )
{
    if (!Event->LastSendStateValid) {
        return FALSE;
    }
    if ((int64_t)Bbr->LossEventsInRound < MaxLossEvents) {
        return FALSE;
    }

    uint64_t InflightAtSend = Event->LastSendStateInflight;
    uint64_t BytesLostInRound = Bbr->BytesLostInRound;

    if (InflightAtSend > 0 && BytesLostInRound > 0) {
        //
        // bytes_lost_in_round > inflight_at_send * loss_threshold
        //
        if (BytesLostInRound * 100 > InflightAtSend * kBbr3LossThresholdPct) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// quic::Bbr2NetworkModel::AdaptLowerBounds() (DEFAULT bw_lo_mode only).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3AdaptLowerBounds(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    if (!Event->EndOfRoundTrip || Event->IsProbingForBandwidth) {
        return;
    }

    if (Bbr->BytesLostInRound > 0) {
        if (Bbr->BandwidthLo == BBR3_INFINITE_BANDWIDTH) {
            Bbr->BandwidthLo = Bbr3MaxBandwidth(Bbr);
        }
        uint64_t Decayed =
            Bbr->BandwidthLo * kBbr3OneMinusBetaNum / kBbr3OneMinusBetaDen;
        Bbr->BandwidthLo = CXPLAT_MAX(Bbr->BandwidthLatest, Decayed);

        if (Bbr->InflightLo == BBR3_INFINITE_INFLIGHT) {
            Bbr->InflightLo = Event->PriorCwnd;
        }
        uint64_t InflightDecayed =
            Bbr->InflightLo * kBbr3OneMinusBetaNum / kBbr3OneMinusBetaDen;
        Bbr->InflightLo = CXPLAT_MAX(Bbr->InflightLatest, InflightDecayed);
    }
}

//
// quic::Bbr2NetworkModel::HasBandwidthGrowth().
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3HasBandwidthGrowth(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    uint64_t MaxBw = Bbr3MaxBandwidth(Bbr);
    uint64_t Threshold =
        Bbr->FullBandwidthBaseline * kBbr3FullBwThresholdNum / kBbr3FullBwThresholdDen;

    if (MaxBw >= Threshold) {
        Bbr->FullBandwidthBaseline = MaxBw;
        Bbr->RoundsWithoutBandwidthGrowth = 0;
        return TRUE;
    }

    Bbr->RoundsWithoutBandwidthGrowth++;
    if (Bbr->RoundsWithoutBandwidthGrowth >= kBbr3StartupFullBwRounds &&
        !Event->LastSendStateAppLimited) {
        Bbr->FullBandwidthReached = TRUE;
    }
    return FALSE;
}

//
// quic::Bbr2NetworkModel::MaybeExpireMinRtt().
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3MaybeExpireMinRtt(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    if (!Bbr->MinRttTimestampValid ||
        Event->EventTime < Bbr->MinRttTimestamp + kBbr3ProbeRttPeriodUs) {
        return FALSE;
    }
    if (Event->SampleMinRtt == UINT64_MAX) {
        return FALSE;
    }
    Bbr->MinRtt = Event->SampleMinRtt;
    Bbr->MinRttTimestamp = Event->EventTime;
    return TRUE;
}

#if BBR3_OVERESTIMATE_AVOIDANCE
//
// ---------------------------------------------------------------------------
// Bandwidth-sampler overestimate avoidance (quic BSAO) helpers.
//
// RecentAckPoints tracks the two most recent ack points at distinct times; the
// a0-candidate ring records the ack point at each ack-aggregation-epoch
// boundary (a "quiet" point). ChooseA0Point picks, for the packet being acked,
// the candidate just at-or-before its send (in total-bytes-acked order), giving
// the ack-rate a long, aggregation-spanning baseline that averages out bursts.
// ---------------------------------------------------------------------------
//

//
// quic::BandwidthSampler::RecentAckPoints::Update().
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RecentAckPointsUpdate(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t AckTime,
    _In_ uint64_t TotalBytesAcked
    )
{
    if (!CxPlatTimeAtOrBefore64(AckTime, Bbr->RecentAckTime[1])) {
        //
        // AckTime > recent: shift recent -> less-recent, advance recent.
        //
        Bbr->RecentAckTime[0] = Bbr->RecentAckTime[1];
        Bbr->RecentAckBytes[0] = Bbr->RecentAckBytes[1];
        Bbr->RecentAckTime[1] = AckTime;
    } else if (!CxPlatTimeAtOrBefore64(Bbr->RecentAckTime[1], AckTime)) {
        //
        // AckTime < recent (time went backwards): keep the smaller timestamp.
        //
        Bbr->RecentAckTime[1] = AckTime;
    }
    Bbr->RecentAckBytes[1] = TotalBytesAcked;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RecentAckPointsClear(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    Bbr->RecentAckTime[0] = Bbr->RecentAckTime[1] = 0;
    Bbr->RecentAckBytes[0] = Bbr->RecentAckBytes[1] = 0;
}

//
// quic::BandwidthSampler::RecentAckPoints::LessRecentPoint(): the older of the
// two points, falling back to the recent one before a second point exists.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RecentAckPointsLessRecent(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _Out_ uint64_t* AckTime,
    _Out_ uint64_t* TotalBytesAcked
    )
{
    if (Bbr->RecentAckBytes[0] != 0) {
        *AckTime = Bbr->RecentAckTime[0];
        *TotalBytesAcked = Bbr->RecentAckBytes[0];
    } else {
        *AckTime = Bbr->RecentAckTime[1];
        *TotalBytesAcked = Bbr->RecentAckBytes[1];
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3A0CandidatesClear(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    Bbr->A0CandHead = 0;
    Bbr->A0CandCount = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3A0CandidatesPushBack(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t AckTime,
    _In_ uint64_t TotalBytesAcked
    )
{
    uint32_t Index;
    if (Bbr->A0CandCount == BBR3_A0_CANDIDATES_MAX) {
        //
        // Ring full: drop the oldest. Falling back to a slightly more recent A0
        // is a safe degradation (a touch less averaging), never incorrect.
        //
        Bbr->A0CandHead = (Bbr->A0CandHead + 1) % BBR3_A0_CANDIDATES_MAX;
        Bbr->A0CandCount--;
    }
    Index = (Bbr->A0CandHead + Bbr->A0CandCount) % BBR3_A0_CANDIDATES_MAX;
    Bbr->A0CandTime[Index] = AckTime;
    Bbr->A0CandBytes[Index] = TotalBytesAcked;
    Bbr->A0CandCount++;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3A0CandidatesPopFrontN(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint32_t Count
    )
{
    if (Count > Bbr->A0CandCount) {
        Count = Bbr->A0CandCount;
    }
    Bbr->A0CandHead = (Bbr->A0CandHead + Count) % BBR3_A0_CANDIDATES_MAX;
    Bbr->A0CandCount -= Count;
}

//
// quic::BandwidthSampler::ChooseA0Point(). Returns FALSE (and leaves outputs
// untouched) when there are no candidates, in which case the caller uses the
// default "last ack before send" A0.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3ChooseA0Point(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t TotalBytesAcked,
    _Out_ uint64_t* A0Time,
    _Out_ uint64_t* A0Bytes
    )
{
    uint32_t i;

    if (Bbr->A0CandCount == 0) {
        return FALSE;
    }
    if (Bbr->A0CandCount == 1) {
        *A0Time = Bbr->A0CandTime[Bbr->A0CandHead];
        *A0Bytes = Bbr->A0CandBytes[Bbr->A0CandHead];
        return TRUE;
    }

    for (i = 1; i < Bbr->A0CandCount; ++i) {
        uint32_t Index = (Bbr->A0CandHead + i) % BBR3_A0_CANDIDATES_MAX;
        if (Bbr->A0CandBytes[Index] > TotalBytesAcked) {
            uint32_t Prev = (Bbr->A0CandHead + i - 1) % BBR3_A0_CANDIDATES_MAX;
            *A0Time = Bbr->A0CandTime[Prev];
            *A0Bytes = Bbr->A0CandBytes[Prev];
            if (i > 1) {
                Bbr3A0CandidatesPopFrontN(Bbr, i - 1);
            }
            return TRUE;
        }
    }

    //
    // All candidates' total_bytes_acked are <= TotalBytesAcked: use the newest.
    //
    {
        uint32_t Back = (Bbr->A0CandHead + Bbr->A0CandCount - 1) % BBR3_A0_CANDIDATES_MAX;
        *A0Time = Bbr->A0CandTime[Back];
        *A0Bytes = Bbr->A0CandBytes[Back];
        Bbr3A0CandidatesPopFrontN(Bbr, Bbr->A0CandCount - 1);
    }
    return TRUE;
}
#endif // BBR3_OVERESTIMATE_AVOIDANCE

//
// Ack-aggregation ("extra acked") tracker, ported from msquic BBRv1 / quic
// MaxAckHeightTracker::Update. Returns TRUE when this ack starts a new
// aggregation epoch (extra_acked == 0), which is the quiet point used to seed
// an overestimate-avoidance A0 candidate.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3UpdateAckAggregation(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t BytesAcked,
    _In_ uint64_t AckTime
    )
{
    if (!Bbr->AckAggregationStartTimeValid) {
        Bbr->AckAggregationStartTimeValid = TRUE;
        Bbr->AckAggregationStartTime = AckTime;
        Bbr->AggregatedAckBytes = BytesAcked;
        return TRUE;
    }

    uint64_t Bandwidth = Bbr3BandwidthEstimate(Bbr); // BW_UNIT-scaled
    if (Bandwidth == BBR3_INFINITE_BANDWIDTH) {
        Bandwidth = Bbr3MaxBandwidth(Bbr);
    }
    uint64_t Elapsed = CxPlatTimeDiff64(Bbr->AckAggregationStartTime, AckTime);
    uint64_t ExpectedAckBytes = Bandwidth * Elapsed / kMicroSecsInSec / BW_UNIT;

    //
    // Reset the epoch if the aggregation is at/below what bandwidth would
    // predict. quic's ack_aggregation_bandwidth_threshold is 2.0 under
    // overestimate avoidance (1.0 otherwise) -- a larger threshold starts new
    // epochs more readily, producing more quiet A0 candidates and a smaller
    // extra-acked (less cwnd inflation from aggregation).
    //
#if BBR3_OVERESTIMATE_AVOIDANCE
    uint64_t ResetThreshold = 2 * ExpectedAckBytes;
#else
    uint64_t ResetThreshold = ExpectedAckBytes;
#endif
    if (Bbr->AggregatedAckBytes <= ResetThreshold) {
        Bbr->AggregatedAckBytes = BytesAcked;
        Bbr->AckAggregationStartTime = AckTime;
        return TRUE;
    }

    Bbr->AggregatedAckBytes += BytesAcked;
    uint64_t ExtraAcked = Bbr->AggregatedAckBytes - ExpectedAckBytes;
    QuicSlidingWindowExtremumUpdateMax(
        &Bbr->MaxAckHeightFilter, ExtraAcked, Bbr->RoundTripCount);
    return FALSE;
}

//
// quic::Bbr2NetworkModel::OnCongestionEventStart(): build the event from
// msquic's ack event plus the buffered loss, update the bandwidth/rtt filters
// and the lower bounds. The per-packet delivery-rate sampling reuses msquic's
// BBRv1 inline approach.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3OnCongestionEventStart(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t PriorBytesInFlight,
    _Inout_ BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    Event->EventTime = AckEvent->TimeNow;
    Event->PriorCwnd = Bbr->CongestionWindow;
    Event->PriorBytesInFlight = PriorBytesInFlight;
    Event->SampleMinRtt = UINT64_MAX;
    Event->SampleMaxBandwidth = 0;
    Event->SampleIsAppLimited = FALSE;

    //
    // Did this ack advance the round trip?
    //
    Event->EndOfRoundTrip = FALSE;
    if (AckEvent->NumRetransmittableBytes > 0) {
        Event->EndOfRoundTrip =
            Bbr3RoundCounterOnPacketsAcked(Bbr, AckEvent->LargestAck);
    }

    //
    // Per-packet delivery-rate sampling -- a faithful port of QUICHE's
    // BandwidthSampler::OnPacketAcknowledgedInner. msquic's per-packet
    // QUIC_SENT_PACKET_METADATA carries the same send-state QUICHE keeps in its
    // connection_state_map (verified: LastAckedPacketInfo.{SentTime,AckTime,
    // TotalBytesSent,TotalBytesAcked} == last_acked_packet_{sent,ack}_time /
    // total_bytes_sent_at_last_acked_packet / send_time_state.total_bytes_acked).
    // For each acked packet, send_rate and ack_rate are computed from its
    // send-state, the sample is min(send,ack), and the per-event sample is the
    // max over packets (carrying that packet's app-limited flag).
    //
    uint64_t TimeNow = AckEvent->TimeNow;
    uint64_t LargestAckedSendTotalBytesAcked = Bbr->TotalBytesAcked;
    uint64_t LargestAckedTotalBytesSent = 0;
    BOOLEAN FoundLargestSendState = FALSE;

#if BBR3_OVERESTIMATE_AVOIDANCE
    //
    // Is there a sustained standing queue right now? If so, the high ack-rate
    // samples are bloat-driven and OE should de-spike them; if not (rtt ~=
    // minRtt, or still in STARTUP), leave the aggressive baseline alone so the
    // estimate tracks the true rate (preserves LAN throughput). The OE state
    // (candidates) is still maintained below regardless, so it can engage the
    // instant a queue forms.
    //
    BOOLEAN OeQueueActive = FALSE;
    if (Bbr->BbrMode != BBR3_MODE_STARTUP &&
        Bbr->MinRttTimestampValid && Bbr->MinRtt != 0 && Bbr->MinRtt != UINT64_MAX &&
        AckEvent->SmoothedRtt >
            Bbr->MinRtt * kBbr3OeQueueRttThreshNum / kBbr3OeQueueRttThreshDen &&
        AckEvent->SmoothedRtt - Bbr->MinRtt > kBbr3OeQueueDelayFloorUs) {
        OeQueueActive = TRUE;
    }
#endif

    QUIC_SENT_PACKET_METADATA* Iter = AckEvent->AckedPackets;
    while (Iter != NULL) {
        QUIC_SENT_PACKET_METADATA* Acked = Iter;
        Iter = Iter->Next;

        if (Acked->PacketNumber == AckEvent->LargestAck &&
            Acked->Flags.HasLastAckedPacketInfo) {
            LargestAckedSendTotalBytesAcked =
                Acked->LastAckedPacketInfo.TotalBytesAcked;
            LargestAckedTotalBytesSent = Acked->TotalBytesSent;
            FoundLargestSendState = TRUE;
        }

        if (Acked->PacketLength == 0) {
            continue;
        }

        uint64_t SendRate = UINT64_MAX;
        uint64_t AckRate = UINT64_MAX;

        if (Acked->Flags.HasLastAckedPacketInfo) {
            //
            // send_rate = (bytes(S1) - bytes(S0)) / (time(S1) - time(S0)).
            //
            uint64_t SendElapsed =
                CxPlatTimeDiff64(Acked->LastAckedPacketInfo.SentTime, Acked->SentTime);
            if (SendElapsed) {
                SendRate =
                    kMicroSecsInSec * BW_UNIT *
                    (Acked->TotalBytesSent - Acked->LastAckedPacketInfo.TotalBytesSent) /
                    SendElapsed;
            }

            //
            // ack_rate = (total_acked - bytes(A0)) / (ack_time - time(A0)).
            // By default A0 is the most recent ack at this packet's send time
            // (delayed-ack-adjusted, matching msquic's BBRv1 sampler). Under
            // overestimate avoidance, A0 is instead an earlier aggregation-epoch
            // quiet point: a longer baseline so that a burst of aggregated acks
            // cannot inflate the rate.
            //
            uint64_t A0Bytes = Acked->LastAckedPacketInfo.TotalBytesAcked;
            uint64_t AckElapsed = 0;
#if BBR3_OVERESTIMATE_AVOIDANCE
            uint64_t A0Time = 0;
            uint64_t ChosenA0Bytes = 0;
            if (OeQueueActive && Bbr3ChooseA0Point(Bbr, A0Bytes, &A0Time, &ChosenA0Bytes)) {
                if (CxPlatTimeAtOrBefore64(TimeNow, A0Time)) {
                    //
                    // Degenerate baseline (ack time not after A0): discard this
                    // packet's sample entirely, as QUICHE does.
                    //
                    continue;
                }
                AckElapsed = CxPlatTimeDiff64(A0Time, TimeNow);
                A0Bytes = ChosenA0Bytes;
            } else
#endif
            if (!CxPlatTimeAtOrBefore64(AckEvent->AdjustedAckTime, Acked->LastAckedPacketInfo.AdjustedAckTime)) {
                AckElapsed = CxPlatTimeDiff64(Acked->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckElapsed = CxPlatTimeDiff64(Acked->LastAckedPacketInfo.AckTime, TimeNow);
            }
            if (AckElapsed &&
                AckEvent->NumTotalAckedRetransmittableBytes > A0Bytes) {
                AckRate =
                    kMicroSecsInSec * BW_UNIT *
                    (AckEvent->NumTotalAckedRetransmittableBytes - A0Bytes) /
                    AckElapsed;
            }
        } else if (!CxPlatTimeAtOrBefore64(TimeNow, Acked->SentTime)) {
            SendRate =
                kMicroSecsInSec * BW_UNIT *
                AckEvent->NumTotalAckedRetransmittableBytes /
                CxPlatTimeDiff64(Acked->SentTime, TimeNow);
        }

        if (SendRate == UINT64_MAX && AckRate == UINT64_MAX) {
            continue;
        }
        uint64_t DeliveryRate = CXPLAT_MIN(SendRate, AckRate);
        if (DeliveryRate > Event->SampleMaxBandwidth) {
            Event->SampleMaxBandwidth = DeliveryRate;
            Event->SampleIsAppLimited = Acked->Flags.IsAppLimited;
        }
    }

    //
    // Inflight when the largest acked packet was SENT: QUICHE's
    // BytesInFlight(send_state) ~= total_bytes_sent(at send) -
    // total_bytes_acked(at send). Using the *current* (post-bloat) inflight here
    // makes inflight_hi/lo chase the bloat instead of capping it, which caused
    // the runaway cwnd / multi-second bufferbloat.
    //
    uint64_t SendTimeInflight = PriorBytesInFlight;
    if (FoundLargestSendState &&
        LargestAckedTotalBytesSent >= LargestAckedSendTotalBytesAcked) {
        SendTimeInflight =
            LargestAckedTotalBytesSent - LargestAckedSendTotalBytesAcked;
    }

    //
    // Send-state of the largest acked packet (proxy values from msquic).
    //
    if (AckEvent->NumRetransmittableBytes > 0) {
        Event->LastSendStateValid = TRUE;
        Event->LastSendStateAppLimited = AckEvent->IsLargestAckedPacketAppLimited;
        Event->LastSendStateInflight = SendTimeInflight;
        Event->LastSendStateTotalBytesAcked = LargestAckedSendTotalBytesAcked;
    }

    //
    // App-limited exit: once we ack past the app-limited target, clear it.
    //
    if (Bbr->AppLimited && Bbr->AppLimitedExitTarget < AckEvent->LargestAck) {
        Bbr->AppLimited = FALSE;
    }

    //
    // Update the 2-slot max-bandwidth filter. Skip an app-limited sample unless
    // it beats the current estimate (quic Bbr2NetworkModel::OnCongestionEventStart
    // uses the sample's own app-limited flag, not the connection-level phase).
    //
    if (Event->SampleMaxBandwidth > 0) {
        if (!Event->SampleIsAppLimited || Event->SampleMaxBandwidth > Bbr3MaxBandwidth(Bbr)) {
            Bbr3MaxBandwidthFilterUpdate(Bbr, Event->SampleMaxBandwidth);
        }
        if (Event->SampleMaxBandwidth > Bbr->BandwidthLatest) {
            Bbr->BandwidthLatest = Event->SampleMaxBandwidth;
        }
    }

    //
    // Min RTT.
    //
    if (AckEvent->MinRttValid) {
        Event->SampleMinRtt = AckEvent->MinRtt;
        if (!Bbr->MinRttTimestampValid || AckEvent->MinRtt < Bbr->MinRtt) {
            Bbr->MinRtt = AckEvent->MinRtt;
            Bbr->MinRttTimestamp = AckEvent->TimeNow;
            Bbr->MinRttTimestampValid = TRUE;
        }
    }

    //
    // Bytes acked / lost for this event (loss was buffered by OnDataLost).
    //
    Event->BytesAcked = AckEvent->NumRetransmittableBytes;
    Bbr->TotalBytesAcked += Event->BytesAcked;

    if (Event->PriorBytesInFlight >= Event->BytesAcked + Event->BytesLost) {
        Event->BytesInFlight =
            Event->PriorBytesInFlight - Event->BytesAcked - Event->BytesLost;
    } else {
        Event->BytesInFlight = 0;
    }

    //
    // max_bytes_delivered_in_round (using the largest acked packet's send-state).
    //
    if (Event->BytesAcked > 0 && Event->LastSendStateValid &&
        Bbr->TotalBytesAcked > Event->LastSendStateTotalBytesAcked) {
        uint64_t BytesDelivered =
            Bbr->TotalBytesAcked - Event->LastSendStateTotalBytesAcked;
        Bbr->MaxBytesDeliveredInRound =
            CXPLAT_MAX(Bbr->MaxBytesDeliveredInRound, BytesDelivered);
    }

    if (Event->BytesInFlight < Bbr->MinBytesInFlightInRound) {
        Bbr->MinBytesInFlightInRound = Event->BytesInFlight;
    }

    //
    // inflight_latest tracks the send-time inflight of recent samples.
    //
    if (SendTimeInflight > Bbr->InflightLatest) {
        Bbr->InflightLatest = SendTimeInflight;
    }

    //
    // Ack aggregation (extra acked). Under overestimate avoidance, advance the
    // ack-line tracker, and when this ack starts a new aggregation epoch record
    // that quiet point as an A0 candidate for future ack-rate samples.
    //
    if (Event->BytesAcked > 0) {
#if BBR3_OVERESTIMATE_AVOIDANCE
        Bbr3RecentAckPointsUpdate(
            Bbr, AckEvent->TimeNow, AckEvent->NumTotalAckedRetransmittableBytes);
        if (Bbr3UpdateAckAggregation(Bbr, Event->BytesAcked, AckEvent->TimeNow)) {
            uint64_t CandTime, CandBytes;
            Bbr3RecentAckPointsLessRecent(Bbr, &CandTime, &CandBytes);
            Bbr3A0CandidatesPushBack(Bbr, CandTime, CandBytes);
        }
#else
        (void)Bbr3UpdateAckAggregation(Bbr, Event->BytesAcked, AckEvent->TimeNow);
#endif
    }

    Bbr3AdaptLowerBounds(Bbr, Event);

    if (Event->EndOfRoundTrip) {
        if (Event->SampleMaxBandwidth > 0) {
            Bbr->BandwidthLatest = Event->SampleMaxBandwidth;
        }
        Bbr->InflightLatest = SendTimeInflight;
    }
}

//
// ---------------------------------------------------------------------------
// PROBE_BW phase logic (quic::Bbr2ProbeBwMode).
// ---------------------------------------------------------------------------
//

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3PacingGainForPhase(
    _In_ uint8_t Phase
    )
{
    if (Phase == BBR3_PROBE_UP) {
        return kBbr3ProbeBwUpPacingGain;
    }
    if (Phase == BBR3_PROBE_DOWN) {
        return kBbr3ProbeBwDownPacingGain;
    }
    return kBbr3ProbeBwDefaultPacingGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3HasCycleLasted(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t Duration,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    return CxPlatTimeDiff64(Bbr->CycleStartTime, Event->EventTime) > Duration;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3HasPhaseLasted(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint64_t Duration,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    return CxPlatTimeDiff64(Bbr->PhaseStartTime, Event->EventTime) > Duration;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3IsTimeToProbeForRenoCoexistence(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint64_t Rounds = kBbr3ProbeBwProbeMaxRounds;
    //
    // probe_bw_probe_reno_gain == 1.0: reno_rounds = target_inflight / MSS.
    //
    uint64_t TargetInflight = Bbr3GetTargetBytesInflight(Cc);
    uint64_t Mss = Bbr3DatagramPayloadLength(Cc);
    uint64_t RenoRounds = (Mss > 0) ? (TargetInflight / Mss) : Rounds;
    Rounds = CXPLAT_MIN(Rounds, RenoRounds);
    return Bbr->RoundsSinceProbe >= Rounds;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3IsTimeToProbeBandwidth(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (Bbr3HasCycleLasted(Bbr, Bbr->ProbeWaitTime, Event)) {
        return TRUE;
    }
    if (Bbr3IsTimeToProbeForRenoCoexistence(Cc)) {
        return TRUE;
    }
    return FALSE;
}

//
// quic::Bbr2ProbeBwMode::MaybeAdaptUpperBounds(). Returns TRUE if the probe
// went too high (ADAPTED_PROBED_TOO_HIGH).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3MaybeAdaptUpperBounds(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (!Event->LastSendStateValid) {
        return FALSE;
    }

    uint64_t InflightAtSend = Event->LastSendStateInflight;

    if (Bbr3IsInflightTooHigh(Bbr, Event, kBbr3ProbeBwFullLossCount)) {
        if (Bbr->IsSampleFromProbing) {
            Bbr->IsSampleFromProbing = FALSE;
            if (!Event->LastSendStateAppLimited) {
                uint64_t InflightTarget =
                    Bbr3GetTargetBytesInflight(Cc) * kBbr3OneMinusBetaNum / kBbr3OneMinusBetaDen;
                Bbr->InflightHi = CXPLAT_MAX(InflightAtSend, InflightTarget);
            }
            return TRUE;
        }
        return FALSE;
    }

    if (Bbr->InflightHi == BBR3_INFINITE_INFLIGHT) {
        return FALSE;
    }

    //
    // Raise the upper bound for inflight.
    //
    if (InflightAtSend > Bbr->InflightHi) {
        Bbr->InflightHi = InflightAtSend;
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RaiseInflightHighSlope(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint64_t GrowthThisRound = (uint64_t)1 << CXPLAT_MIN(Bbr->ProbeUpRounds, (uint64_t)30);
    Bbr->ProbeUpRounds = CXPLAT_MIN(Bbr->ProbeUpRounds + 1, (uint64_t)30);
    uint64_t ProbeUpBytes = Bbr3CongestionControlGetCongestionWindow(Cc) / GrowthThisRound;
    Bbr->ProbeUpBytes = CXPLAT_MAX(ProbeUpBytes, (uint64_t)Bbr3DatagramPayloadLength(Cc));
}

//
// quic::Bbr2ProbeBwMode::ProbeInflightHighUpward(). With the default
// probe_up_ignore_inflight_hi == true, inflight_hi is not raised here.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeInflightHighUpward(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Cc);
    UNREFERENCED_PARAMETER(Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwExitProbeDown(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (!Bbr->HasAdvancedMaxBw) {
        Bbr3MaxBandwidthFilterAdvance(Bbr);
        Bbr->HasAdvancedMaxBw = TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeDown(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN ProbedTooHigh,
    _In_ BOOLEAN StoppedRiskyProbe,
    _In_ uint64_t Now
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    Bbr->LastCycleProbedTooHigh = ProbedTooHigh;
    Bbr->LastCycleStoppedRiskyProbe = StoppedRiskyProbe;

    Bbr->CycleStartTime = Now;
    Bbr->ProbePhase = BBR3_PROBE_DOWN;
    Bbr->RoundsInPhase = 0;
    Bbr->PhaseStartTime = Now;

    //
    // Pick the probe wait time: base + random(0, max_rand).
    //
    uint32_t Rand32 = 0;
    CxPlatRandom(sizeof(Rand32), &Rand32);
    Bbr->RoundsSinceProbe = Rand32 % kBbr3ProbeBwMaxProbeRandRounds;

    uint32_t Rand32b = 0;
    CxPlatRandom(sizeof(Rand32b), &Rand32b);
    Bbr->ProbeWaitTime =
        kBbr3ProbeBwProbeBaseDurationUs +
        (Rand32b % kBbr3ProbeBwProbeMaxRandDurationUs);

    Bbr->ProbeUpBytes = UINT64_MAX;
    Bbr->HasAdvancedMaxBw = FALSE;
    Bbr3RestartRoundEarly(Bbr);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeCruise(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t Now
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (Bbr->ProbePhase == BBR3_PROBE_DOWN) {
        Bbr3ProbeBwExitProbeDown(Cc);
    }
    //
    // cap_inflight_lo(inflight_hi).
    //
    if (Bbr->InflightLo != BBR3_INFINITE_INFLIGHT && Bbr->InflightLo > Bbr->InflightHi) {
        Bbr->InflightLo = Bbr->InflightHi;
    }
    Bbr->ProbePhase = BBR3_PROBE_CRUISE;
    Bbr->RoundsInPhase = 0;
    Bbr->PhaseStartTime = Now;
    Bbr->IsSampleFromProbing = FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeRefill(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t ProbeUpRounds,
    _In_ uint64_t Now
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (Bbr->ProbePhase == BBR3_PROBE_DOWN) {
        Bbr3ProbeBwExitProbeDown(Cc);
    }
    Bbr->ProbePhase = BBR3_PROBE_REFILL;
    Bbr->RoundsInPhase = 0;
    Bbr->PhaseStartTime = Now;
    Bbr->IsSampleFromProbing = FALSE;
    Bbr->LastCycleStoppedRiskyProbe = FALSE;

    Bbr->BandwidthLo = BBR3_INFINITE_BANDWIDTH;
    Bbr->InflightLo = BBR3_INFINITE_INFLIGHT;
    Bbr->ProbeUpRounds = ProbeUpRounds;
    Bbr->ProbeUpAcked = 0;
    Bbr3RestartRoundEarly(Bbr);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnterProbeUp(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t Now
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    Bbr->ProbePhase = BBR3_PROBE_UP;
    Bbr->RoundsInPhase = 0;
    Bbr->PhaseStartTime = Now;
    Bbr->IsSampleFromProbing = TRUE;
    Bbr3RaiseInflightHighSlope(Cc);
    Bbr3RestartRoundEarly(Bbr);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3UpdateProbeDown(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t PriorInFlight,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    if (Bbr->RoundsInPhase == 1 && Event->EndOfRoundTrip) {
        Bbr->IsSampleFromProbing = FALSE;
        if (!Event->LastSendStateAppLimited) {
            Bbr3MaxBandwidthFilterAdvance(Bbr);
            Bbr->HasAdvancedMaxBw = TRUE;
        }
        if (Bbr->LastCycleStoppedRiskyProbe && !Bbr->LastCycleProbedTooHigh) {
            Bbr3ProbeBwEnterProbeRefill(Cc, 0, Event->EventTime);
            return;
        }
    }

    Bbr3MaybeAdaptUpperBounds(Cc, Event);

    if (Bbr3IsTimeToProbeBandwidth(Cc, Event)) {
        Bbr3ProbeBwEnterProbeRefill(Cc, 0, Event->EventTime);
        return;
    }

    //
    // Stay in PROBE_DOWN for at most a min-rtt (BBRv1-style).
    //
    if (Bbr3HasPhaseLasted(Bbr, Bbr->MinRtt, Event)) {
        Bbr3ProbeBwEnterProbeCruise(Cc, Event->EventTime);
        return;
    }

    UNREFERENCED_PARAMETER(PriorInFlight);
    uint64_t InflightWithHeadroom = Bbr3InflightHiWithHeadroom(Bbr);
    if (Event->BytesInFlight > InflightWithHeadroom) {
        return; // Stay in PROBE_DOWN.
    }

    uint64_t Bdp = Bbr3Bdp(Bbr, Bbr3BandwidthEstimate(Bbr));
    if (Event->BytesInFlight < Bdp) {
        Bbr3ProbeBwEnterProbeCruise(Cc, Event->EventTime);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3UpdateProbeCruise(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    Bbr3MaybeAdaptUpperBounds(Cc, Event);
    if (Bbr3IsTimeToProbeBandwidth(Cc, Event)) {
        Bbr3ProbeBwEnterProbeRefill(Cc, 0, Event->EventTime);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3UpdateProbeRefill(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    Bbr3MaybeAdaptUpperBounds(Cc, Event);
    if (Bbr->RoundsInPhase > 0 && Event->EndOfRoundTrip) {
        Bbr3ProbeBwEnterProbeUp(Cc, Event->EventTime);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3UpdateProbeUp(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t PriorInFlight,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (Bbr3MaybeAdaptUpperBounds(Cc, Event)) {
        Bbr3ProbeBwEnterProbeDown(Cc, TRUE, FALSE, Event->EventTime);
        return;
    }

    Bbr3ProbeInflightHighUpward(Cc, Event);

    BOOLEAN IsRisky = FALSE;
    BOOLEAN IsQueuing = FALSE;
    if (Bbr->LastCycleProbedTooHigh && PriorInFlight >= Bbr->InflightHi) {
        IsRisky = TRUE;
    } else if (Bbr->RoundsInPhase > 0) {
        uint64_t QueuingThresholdExtra = Bbr3QueueingThresholdExtraBytes(Cc);
        QueuingThresholdExtra += Bbr3MaxAckHeight(Bbr); // add_ack_height_to_queueing_threshold
        uint64_t QueuingThreshold =
            (Bbr3Bdp(Bbr, Bbr3BandwidthEstimate(Bbr)) * kBbr3FullBwThresholdNum / kBbr3FullBwThresholdDen) +
            QueuingThresholdExtra;
        IsQueuing = Event->BytesInFlight >= QueuingThreshold;
    }

    if (IsRisky || IsQueuing) {
        Bbr3ProbeBwEnterProbeDown(Cc, FALSE, IsRisky, Event->EventTime);
    }
}

//
// quic::Bbr2ProbeBwMode::OnCongestionEvent().
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
Bbr3ProbeBwOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t PriorInFlight,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint8_t PhaseBefore = Bbr->ProbePhase;

    if (Event->EndOfRoundTrip) {
        if (Bbr->CycleStartTime != Event->EventTime) {
            Bbr->RoundsSinceProbe++;
        }
        if (Bbr->PhaseStartTime != Event->EventTime) {
            Bbr->RoundsInPhase++;
        }
    }

    BOOLEAN SwitchToProbeRtt = FALSE;

    if (Bbr->ProbePhase == BBR3_PROBE_UP) {
        Bbr3UpdateProbeUp(Cc, PriorInFlight, Event);
    } else if (Bbr->ProbePhase == BBR3_PROBE_DOWN) {
        Bbr3UpdateProbeDown(Cc, PriorInFlight, Event);
        if (Bbr->ProbePhase != BBR3_PROBE_DOWN &&
            Bbr3MaybeExpireMinRtt(Bbr, Event)) {
            SwitchToProbeRtt = TRUE;
        }
    } else if (Bbr->ProbePhase == BBR3_PROBE_CRUISE) {
        Bbr3UpdateProbeCruise(Cc, Event);
    } else if (Bbr->ProbePhase == BBR3_PROBE_REFILL) {
        Bbr3UpdateProbeRefill(Cc, Event);
    }

    if (!SwitchToProbeRtt) {
        Bbr->PacingGain = Bbr3PacingGainForPhase(Bbr->ProbePhase);
        Bbr->CwndGain = kBbr3ProbeBwCwndGain;
    }

    if (Bbr->ProbePhase != PhaseBefore) {
        Bbr3LogState(Cc, "phase");
    }

    return SwitchToProbeRtt ? BBR3_MODE_PROBE_RTT : BBR3_MODE_PROBE_BW;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeBwEnter(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t Now
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    if (Bbr->ProbePhase == BBR3_PROBE_NOT_STARTED) {
        Bbr3ProbeBwEnterProbeDown(Cc, FALSE, FALSE, Now);
    } else {
        Bbr->CycleStartTime = Now;
        if (Bbr->ProbePhase == BBR3_PROBE_CRUISE) {
            Bbr3ProbeBwEnterProbeCruise(Cc, Now);
        } else if (Bbr->ProbePhase == BBR3_PROBE_REFILL) {
            Bbr3ProbeBwEnterProbeRefill(Cc, Bbr->ProbeUpRounds, Now);
        }
    }
}

//
// ---------------------------------------------------------------------------
// STARTUP / DRAIN / PROBE_RTT modes.
// ---------------------------------------------------------------------------
//

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
Bbr3StartupOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    if (Bbr->FullBandwidthReached) {
        return BBR3_MODE_DRAIN;
    }
    if (!Event->EndOfRoundTrip) {
        return BBR3_MODE_STARTUP;
    }

    BOOLEAN HasBwGrowth = Bbr3HasBandwidthGrowth(Bbr, Event);

    //
    // Check excessive losses if not app-limited and no bandwidth growth.
    //
    if (!Event->LastSendStateAppLimited && !HasBwGrowth) {
        if (!Bbr->FullBandwidthReached &&
            Bbr3IsInflightTooHigh(Bbr, Event, kBbr3StartupFullLossCount)) {
            uint64_t NewInflightHi = Bbr3Bdp(Bbr, Bbr3BandwidthEstimate(Bbr));
            //
            // startup_loss_exit_use_max_delivered_for_inflight_hi (default true).
            //
            if (NewInflightHi < Bbr->MaxBytesDeliveredInRound) {
                NewInflightHi = Bbr->MaxBytesDeliveredInRound;
            }
            Bbr->InflightHi = NewInflightHi;
            Bbr->FullBandwidthReached = TRUE;
        }
    }

    return Bbr->FullBandwidthReached ? BBR3_MODE_DRAIN : BBR3_MODE_STARTUP;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3DrainTarget(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint64_t Bdp = Bbr3Bdp(Bbr, Bbr3BandwidthEstimate(Bbr));
    return CXPLAT_MAX(Bdp, (uint64_t)Bbr3GetMinimumCongestionWindow(Bbr));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
Bbr3DrainOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    Bbr->PacingGain = kBbr3DrainPacingGain;
    Bbr->CwndGain = kBbr3DrainCwndGain;

    if (Event->BytesInFlight <= Bbr3DrainTarget(Cc)) {
        return BBR3_MODE_PROBE_BW;
    }
    return BBR3_MODE_DRAIN;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3ProbeRttInflightTarget(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    uint64_t Bdp = Bbr3Bdp(Bbr, Bbr3MaxBandwidth(Bbr));
    return Bdp * kBbr3ProbeRttInflightFractionNum / kBbr3ProbeRttInflightFractionDen;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3ProbeRttEnter(
    _Inout_ QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    Bbr->PacingGain = GAIN_UNIT;
    Bbr->CwndGain = GAIN_UNIT;
    Bbr->ProbeRttExitTimeValid = FALSE;
    Bbr->ProbeRttExitTime = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
Bbr3ProbeRttOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const BBR3_CONGESTION_EVENT* Event
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    if (!Bbr->ProbeRttExitTimeValid) {
        if (Event->BytesInFlight <= Bbr3ProbeRttInflightTarget(Bbr) ||
            Event->BytesInFlight <= Bbr3GetMinimumCongestionWindow(Bbr)) {
            Bbr->ProbeRttExitTime = Event->EventTime + kBbr3ProbeRttDurationUs;
            Bbr->ProbeRttExitTimeValid = TRUE;
        }
        return BBR3_MODE_PROBE_RTT;
    }

    return Event->EventTime > Bbr->ProbeRttExitTime ? BBR3_MODE_PROBE_BW
                                                    : BBR3_MODE_PROBE_RTT;
}

//
// ---------------------------------------------------------------------------
// Mode dispatch helpers.
// ---------------------------------------------------------------------------
//

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3IsProbingForBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    if (Bbr->BbrMode == BBR3_MODE_STARTUP) {
        return TRUE;
    }
    if (Bbr->BbrMode == BBR3_MODE_PROBE_BW) {
        return Bbr->ProbePhase == BBR3_PROBE_REFILL ||
               Bbr->ProbePhase == BBR3_PROBE_UP;
    }
    return FALSE;
}

//
// Mode-specific cwnd upper bound (quic::Bbr2Sender::GetCwndLimitsByMode()).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3GetCwndUpperLimitByMode(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr
    )
{
    switch (Bbr->BbrMode) {
    case BBR3_MODE_STARTUP:
    case BBR3_MODE_DRAIN:
        return Bbr->InflightLo;
    case BBR3_MODE_PROBE_BW:
        if (Bbr->ProbePhase == BBR3_PROBE_CRUISE) {
            return CXPLAT_MIN(Bbr->InflightLo, Bbr3InflightHiWithHeadroom(Bbr));
        }
        if (Bbr->ProbePhase == BBR3_PROBE_UP) {
            // probe_up_ignore_inflight_hi default true: limited by inflight_lo.
            return Bbr->InflightLo;
        }
        return CXPLAT_MIN(Bbr->InflightLo, Bbr->InflightHi);
    case BBR3_MODE_PROBE_RTT: {
        uint64_t Upper = CXPLAT_MIN(Bbr->InflightLo, Bbr3InflightHiWithHeadroom(Bbr));
        return CXPLAT_MIN(Upper, Bbr3ProbeRttInflightTarget(Bbr));
    }
    default:
        return BBR3_INFINITE_INFLIGHT;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3GetTargetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL_BBR3* Bbr,
    _In_ uint32_t GainFp
    )
{
    uint64_t Target = Bbr3BdpWithGain(Bbr, Bbr3BandwidthEstimate(Bbr), GainFp);
    if (Target < Bbr->MinimumCongestionWindow) {
        Target = Bbr->MinimumCongestionWindow;
    }
    return (uint32_t)CXPLAT_MIN(Target, (uint64_t)UINT32_MAX);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3UpdateCongestionWindow(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t BytesAcked
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    uint64_t TargetCwnd = Bbr3GetTargetCongestionWindow(Bbr, Bbr->CwndGain);
    uint64_t PriorCwnd = Bbr->CongestionWindow;
    uint64_t NewCwnd = PriorCwnd;

    if (Bbr->FullBandwidthReached) {
        TargetCwnd += Bbr3MaxAckHeight(Bbr);
        NewCwnd = CXPLAT_MIN(PriorCwnd + BytesAcked, TargetCwnd);
    } else if (PriorCwnd < TargetCwnd || PriorCwnd < 2 * (uint64_t)Bbr->InitialCongestionWindow) {
        NewCwnd = PriorCwnd + BytesAcked;
    }

    //
    // Apply mode limits then the global minimum.
    //
    uint64_t ModeUpper = Bbr3GetCwndUpperLimitByMode(Bbr);
    NewCwnd = CXPLAT_MIN(NewCwnd, ModeUpper);
    NewCwnd = CXPLAT_MAX(NewCwnd, (uint64_t)Bbr->MinimumCongestionWindow);

    Bbr->CongestionWindow = (uint32_t)CXPLAT_MIN(NewCwnd, (uint64_t)UINT32_MAX);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3UpdatePacingRate(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t BytesAcked
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    uint64_t BwEst = Bbr3BandwidthEstimate(Bbr);
    if (BwEst == 0 || BwEst == BBR3_INFINITE_BANDWIDTH) {
        return;
    }

    //
    // After the very first ack, set pacing from the initial window.
    //
    if (Bbr->TotalBytesAcked == BytesAcked) {
        if (Bbr->MinRttTimestampValid && Bbr->MinRtt > 0 && Bbr->MinRtt != UINT64_MAX) {
            Bbr->PacingRate =
                (uint64_t)Bbr->CongestionWindow * BW_UNIT * kMicroSecsInSec / Bbr->MinRtt;
        }
        return;
    }

    uint64_t TargetRate = (uint64_t)Bbr->PacingGain * BwEst / GAIN_UNIT;
    if (Bbr->FullBandwidthReached) {
        Bbr->PacingRate = TargetRate;
        return;
    }

    //
    // By default the pacing rate never decreases in STARTUP.
    //
    if (TargetRate > Bbr->PacingRate) {
        Bbr->PacingRate = TargetRate;
    }
}

//
// quic::Bbr2Sender::GetTargetBytesInflight() == min(BDP, cwnd).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
Bbr3GetTargetBytesInflight(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint64_t Bdp = Bbr3Bdp(Bbr, Bbr3BandwidthEstimate(Bbr));
    return CXPLAT_MIN(Bdp, (uint64_t)Bbr->CongestionWindow);
}

//
// ---------------------------------------------------------------------------
// The main congestion-event driver (quic::Bbr2Sender::OnCongestionEvent()).
// ---------------------------------------------------------------------------
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3HandleCongestionEvent(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t PriorBytesInFlight,
    _In_ uint64_t BufferedBytesLost
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    BBR3_CONGESTION_EVENT Event;
    CxPlatZeroMemory(&Event, sizeof(Event));
    Event.BytesLost = BufferedBytesLost;
    Event.IsProbingForBandwidth = Bbr3IsProbingForBandwidth(Bbr);

    Bbr3OnCongestionEventStart(Cc, AckEvent, PriorBytesInFlight, &Event);

    //
    // Run the current mode, allowing a bounded number of mode changes.
    //
    int ModeChangesAllowed = kBbr3MaxModeChangesPerCongestionEvent;
    for (;;) {
        uint8_t NextMode;
        switch (Bbr->BbrMode) {
        case BBR3_MODE_STARTUP:
            NextMode = Bbr3StartupOnCongestionEvent(Cc, &Event);
            break;
        case BBR3_MODE_DRAIN:
            NextMode = Bbr3DrainOnCongestionEvent(Cc, &Event);
            break;
        case BBR3_MODE_PROBE_BW:
            NextMode = Bbr3ProbeBwOnCongestionEvent(Cc, PriorBytesInFlight, &Event);
            break;
        case BBR3_MODE_PROBE_RTT:
            NextMode = Bbr3ProbeRttOnCongestionEvent(Cc, &Event);
            break;
        default:
            NextMode = Bbr->BbrMode;
            break;
        }

        if (NextMode == Bbr->BbrMode) {
            break;
        }

        //
        // Leave the old mode.
        //
        if (Bbr->BbrMode == BBR3_MODE_STARTUP) {
            // Leave STARTUP: clear bandwidth_lo.
            Bbr->BandwidthLo = BBR3_INFINITE_BANDWIDTH;
        }

        Bbr->BbrMode = NextMode;

        //
        // Enter the new mode.
        //
        if (NextMode == BBR3_MODE_PROBE_BW) {
            Bbr3ProbeBwEnter(Cc, Event.EventTime);
        } else if (NextMode == BBR3_MODE_PROBE_RTT) {
            Bbr3ProbeRttEnter(Bbr);
        }

        Bbr3LogState(Cc, "mode");

        if (--ModeChangesAllowed < 0) {
            break;
        }
    }

    Bbr3UpdatePacingRate(Cc, Event.BytesAcked);
    Bbr3UpdateCongestionWindow(Cc, Event.BytesAcked);

    if (Event.LastSendStateValid && !Event.LastSendStateAppLimited) {
        Bbr->HasNonAppLimitedSample = TRUE;
    }

    //
    // End of round: reset the per-round accumulators.
    //
    if (Event.EndOfRoundTrip) {
        Bbr3OnNewRound(Bbr);
    }
}

//
// ---------------------------------------------------------------------------
// QUIC_CONGESTION_CONTROL vtable implementation.
// ---------------------------------------------------------------------------
//

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    return Bbr->BytesInFlight < Bbr3CongestionControlGetCongestionWindow(Cc) ||
           Bbr->Exemptions > 0;
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
uint32_t
Bbr3CongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr3.CongestionWindow;
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
BOOLEAN
Bbr3CongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr3.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlSetAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    if (Bbr->BytesInFlight > Bbr3CongestionControlGetCongestionWindow(Cc)) {
        return;
    }
    Bbr->AppLimited = TRUE;
    Bbr->AppLimitedExitTarget = Connection->LossDetection.LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
Bbr3CongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend,
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint32_t CongestionWindow = Bbr3CongestionControlGetCongestionWindow(Cc);

    if (Bbr->BytesInFlight >= CongestionWindow) {
        return 0;
    }

    uint32_t Available = CongestionWindow - Bbr->BytesInFlight;

    if (!TimeSinceLastSendValid || Bbr->PacingRate == 0) {
        //
        // No pacing information yet: allow up to the congestion window.
        //
        return Available;
    }

    //
    // Pacing allowance = pacing_rate * elapsed. PacingRate is BW_UNIT-scaled.
    //
    uint64_t PacingBytes =
        Bbr->PacingRate * TimeSinceLastSend / kMicroSecsInSec / BW_UNIT;

    if (PacingBytes >= Available) {
        return Available;
    }
    return (uint32_t)PacingBytes;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    uint64_t PriorBytesInFlight = Bbr->BytesInFlight;
    if (PriorBytesInFlight < Bbr->MinBytesInFlightInRound) {
        Bbr->MinBytesInFlightInRound = PriorBytesInFlight;
    }
    if (Bbr->InflightHi != BBR3_INFINITE_INFLIGHT &&
        PriorBytesInFlight + NumRetransmittableBytes >= Bbr->InflightHi) {
        Bbr->InflightHiLimitedInRound = TRUE;
    }

#if BBR3_OVERESTIMATE_AVOIDANCE
    if (PriorBytesInFlight == 0 && NumRetransmittableBytes > 0) {
        //
        // Fresh send after the network drained: reset the ack-line history and
        // seed an A0 candidate at "now" (quic BandwidthSampler::OnPacketSent
        // bytes_in_flight == 0 case), so sampling has a baseline immediately.
        //
        uint64_t Now = CxPlatTimeUs64();
        Bbr3RecentAckPointsClear(Bbr);
        Bbr3RecentAckPointsUpdate(Bbr, Now, Bbr->TotalBytesAcked);
        Bbr3A0CandidatesClear(Bbr);
        Bbr3A0CandidatesPushBack(Bbr, Now, Bbr->TotalBytesAcked);
    }
#endif

    Bbr3RoundCounterOnPacketSent(Bbr, Connection->LossDetection.LargestSentPacketNumber);

    Bbr->BytesInFlight += NumRetransmittableBytes;
    if (Bbr->BytesInFlight > Bbr->BytesInFlightMax) {
        Bbr->BytesInFlightMax = Bbr->BytesInFlight;
    }
    Bbr->TotalBytesSent += NumRetransmittableBytes;

    if (Bbr->Exemptions > 0) {
        Bbr->Exemptions--;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    BOOLEAN PreviousCanSendState = Bbr3CongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= NumRetransmittableBytes);
    Bbr->BytesInFlight -= NumRetransmittableBytes;

    return PreviousCanSendState == FALSE && Bbr3CongestionControlCanSend(Cc);
}

#if BBR3_RESTART_FROM_IDLE
//
// Soft STARTUP re-entry after a delivery stall (a bad-link "dead window").
// Mirrors the STARTUP portion of Bbr3CongestionControlInitialize: it lifts the
// loss-decayed bandwidth/inflight bounds back to "infinite", restores the
// aggressive STARTUP gains, and resets full-bandwidth detection, so the resumed
// flow re-ramps like a fresh connection. It deliberately PRESERVES MinRtt, the
// max-bandwidth filter, byte totals and the live cwnd / in-flight accounting,
// and does NOT touch the pending-loss accumulator that the current ack pass is
// about to fold in, so it is cheaper and better-informed than an actual
// reconnect.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3RestartFromIdle(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    Bbr->BbrMode = BBR3_MODE_STARTUP;
    Bbr->ProbePhase = BBR3_PROBE_NOT_STARTED;
    Bbr->CwndGain = kBbr3StartupCwndGain;
    Bbr->PacingGain = kBbr3StartupPacingGain;

    Bbr->BandwidthLo = BBR3_INFINITE_BANDWIDTH;
    Bbr->InflightLo = BBR3_INFINITE_INFLIGHT;
    Bbr->InflightHi = BBR3_INFINITE_INFLIGHT;

    Bbr->FullBandwidthReached = FALSE;
    Bbr->FullBandwidthBaseline = 0;
    Bbr->RoundsWithoutBandwidthGrowth = 0;
    Bbr->InflightHiLimitedInRound = FALSE;

    Bbr3LogState(Cc, "idle-restart");
}
#endif // BBR3_RESTART_FROM_IDLE

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Bbr3CongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    BOOLEAN PreviousCanSendState = Bbr3CongestionControlCanSend(Cc);

#if BBR3_RESTART_FROM_IDLE
    //
    // If delivery stalled (no acks arrived) for longer than the threshold and we
    // are not already ramping in STARTUP, treat this ack as a restart from idle:
    // re-enter STARTUP so the path is re-probed in a few RTTs instead of crawling
    // back up through a full PROBE_BW cycle. The threshold is well above normal
    // per-RTT ack spacing, so this never fires during a healthy transfer.
    //
    if (Bbr->LastAckTimeValid && Bbr->BbrMode != BBR3_MODE_STARTUP) {
        uint64_t IdleThreshold = kBbr3RestartIdleFloorUs;
        uint64_t RttThreshold =
            (uint64_t)AckEvent->SmoothedRtt * kBbr3RestartIdleRttMultiple;
        if (RttThreshold > IdleThreshold) {
            IdleThreshold = RttThreshold;
        }
        if (AckEvent->TimeNow > Bbr->LastAckTime &&
            AckEvent->TimeNow - Bbr->LastAckTime > IdleThreshold) {
            Bbr3RestartFromIdle(Cc);
        }
    }
    Bbr->LastAckTime = AckEvent->TimeNow;
    Bbr->LastAckTimeValid = TRUE;
#endif // BBR3_RESTART_FROM_IDLE

    //
    // BytesInFlight currently excludes bytes already removed by OnDataLost
    // during this same ACK pass. Reconstruct the pre-loss inflight for the
    // congestion event, then apply the acked bytes.
    //
    uint64_t BufferedBytesLost = Bbr->BytesLostInRoundPending;
    uint64_t PriorBytesInFlight = (uint64_t)Bbr->BytesInFlight + BufferedBytesLost;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    Bbr3HandleCongestionEvent(Cc, AckEvent, PriorBytesInFlight, BufferedBytesLost);

    //
    // The buffered loss has now been folded into a congestion event.
    //
    Bbr->BytesLostInRoundPending = 0;

    return PreviousCanSendState == FALSE && Bbr3CongestionControlCanSend(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    Connection->Stats.Send.CongestionCount++;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    //
    // Accumulate the loss into the current round. It will be folded into a
    // congestion event by the next OnDataAcknowledged (msquic processes loss
    // before the ack within the same pass).
    //
    Bbr->TotalBytesLost += LossEvent->NumRetransmittableBytes;
    Bbr->BytesLostInRound += LossEvent->NumRetransmittableBytes;
    Bbr->BytesLostInRoundPending += LossEvent->NumRetransmittableBytes;
    Bbr->LossEventsInRound++;
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
Bbr3CongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    UNREFERENCED_PARAMETER(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    );

//
// BBRv3 ECN response. msquic invokes this on a validated CE mark, and ONLY when
// the path is ECN-capable (ECN_VALIDATION_CAPABLE) -- on a path that does not
// mark/echo ECN, validation fails and this never fires, so enabling ECN is safe
// and inert on non-ECN links. The msquic CE signal is coarse ("a new CE
// happened", no fraction), so we respond like cubic: at most one multiplicative
// backoff per round (deduped by the recovery packet number), easing cwnd, the
// inflight bounds and the short-term bandwidth bound by the same beta (x7/10)
// the loss/too-high path uses. Reducing inflight_hi/lo caps cwnd (via
// GetCwndUpperLimitByMode) and bandwidth_lo caps pacing, so the backoff persists
// past this ack; the direct cwnd cut makes it take effect immediately.
//
// This composes with rtt-gated OE: on an ECN-marking link the AQM marks CE
// before the queue inflates the rtt, so OE stays dormant and ECN does the
// precise, low-latency backoff; on a non-marking link ECN is silent and OE is
// the delay-based fallback. (First cut -- if the link proves ECN-capable and
// this needs to be gentler/sharper, fold ECN into the round congestion model.)
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlOnEcn(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ECN_EVENT* EcnEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;

    //
    // At most one backoff per round: ignore CEs for packets sent at/before the
    // last backoff point.
    //
    if (Bbr->EcnRecoveryValid &&
        EcnEvent->LargestPacketNumberAcked <= Bbr->EcnRecoverySentPacketNumber) {
        return;
    }
    Bbr->EcnRecoverySentPacketNumber = EcnEvent->LargestSentPacketNumber;
    Bbr->EcnRecoveryValid = TRUE;
    QuicCongestionControlGetConnection(Cc)->Stats.Send.EcnCongestionCount++;

    uint64_t MinCwnd = Bbr3GetMinimumCongestionWindow(Bbr);
    uint64_t NewCwnd =
        CXPLAT_MAX(
            MinCwnd,
            (uint64_t)Bbr->CongestionWindow * kBbr3OneMinusBetaNum / kBbr3OneMinusBetaDen);

    //
    // Cap the inflight bounds so the next UpdateCongestionWindow does not undo
    // the backoff (inflight_lo bounds cwnd in STARTUP/DRAIN, inflight_hi in
    // PROBE_BW).
    //
    if (Bbr->InflightHi == BBR3_INFINITE_INFLIGHT || Bbr->InflightHi > NewCwnd) {
        Bbr->InflightHi = NewCwnd;
    }
    if (Bbr->InflightLo == BBR3_INFINITE_INFLIGHT || Bbr->InflightLo > NewCwnd) {
        Bbr->InflightLo = NewCwnd;
    }

    //
    // Ease the short-term bandwidth bound so pacing backs off too.
    //
    uint64_t Bw = Bbr3BandwidthEstimate(Bbr);
    if (Bw != BBR3_INFINITE_BANDWIDTH && Bw != 0) {
        uint64_t NewBwLo = Bw * kBbr3OneMinusBetaNum / kBbr3OneMinusBetaDen;
        if (Bbr->BandwidthLo == BBR3_INFINITE_BANDWIDTH || Bbr->BandwidthLo > NewBwLo) {
            Bbr->BandwidthLo = NewBwLo;
        }
    }

    //
    // Apply the cwnd cut immediately.
    //
    Bbr->CongestionWindow = (uint32_t)CXPLAT_MIN(NewCwnd, (uint64_t)UINT32_MAX);
}

static const QUIC_CONGESTION_CONTROL QuicCongestionControlBbr3 = {
    .Name = "BBR3",
    .QuicCongestionControlCanSend = Bbr3CongestionControlCanSend,
    .QuicCongestionControlSetExemption = Bbr3CongestionControlSetExemption,
    .QuicCongestionControlReset = Bbr3CongestionControlReset,
    .QuicCongestionControlGetSendAllowance = Bbr3CongestionControlGetSendAllowance,
    .QuicCongestionControlGetCongestionWindow = Bbr3CongestionControlGetCongestionWindow,
    .QuicCongestionControlOnDataSent = Bbr3CongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = Bbr3CongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = Bbr3CongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = Bbr3CongestionControlOnDataLost,
    .QuicCongestionControlOnEcn = Bbr3CongestionControlOnEcn,
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

    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    const uint16_t DatagramPayloadLength = Bbr3DatagramPayloadLength(Cc);

    Bbr->BbrMode = BBR3_MODE_STARTUP;
    Bbr->ProbePhase = BBR3_PROBE_NOT_STARTED;

    Bbr->InitialCongestionWindowPackets = Settings->InitialWindowPackets;
    Bbr->CongestionWindow = Settings->InitialWindowPackets * DatagramPayloadLength;
    Bbr->InitialCongestionWindow = Settings->InitialWindowPackets * DatagramPayloadLength;
    Bbr->MinimumCongestionWindow = kBbr3MinCwndInMss * DatagramPayloadLength;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;
    Bbr->BytesInFlight = 0;
    Bbr->Exemptions = 0;

    Bbr->CwndGain = kBbr3StartupCwndGain;
    Bbr->PacingGain = kBbr3StartupPacingGain;
    Bbr->PacingRate = 0;

    Bbr->RoundTripCount = 0;
    Bbr->LastSentPacketNumber = 0;
    Bbr->LastSentPacketValid = FALSE;
    Bbr->EndOfRoundTrip = 0;
    Bbr->EndOfRoundTripValid = FALSE;
    Bbr->EcnRecoverySentPacketNumber = 0;
    Bbr->EcnRecoveryValid = FALSE;

    Bbr->MaxBandwidth[0] = 0;
    Bbr->MaxBandwidth[1] = 0;
    Bbr->BandwidthLatest = 0;
    Bbr->BandwidthLo = BBR3_INFINITE_BANDWIDTH;

    Bbr->MinRtt = UINT64_MAX;
    Bbr->MinRttTimestamp = 0;
    Bbr->MinRttTimestampValid = FALSE;

    Bbr->InflightLatest = 0;
    Bbr->InflightLo = BBR3_INFINITE_INFLIGHT;
    Bbr->InflightHi = BBR3_INFINITE_INFLIGHT;

    Bbr->BytesLostInRound = 0;
    Bbr->BytesLostInRoundPending = 0;
    Bbr->LossEventsInRound = 0;
    Bbr->MaxBytesDeliveredInRound = 0;
    Bbr->MinBytesInFlightInRound = UINT64_MAX;
    Bbr->InflightHiLimitedInRound = FALSE;

    Bbr->FullBandwidthReached = FALSE;
    Bbr->FullBandwidthBaseline = 0;
    Bbr->RoundsWithoutBandwidthGrowth = 0;

    Bbr->AppLimited = FALSE;
    Bbr->AppLimitedExitTarget = 0;
    Bbr->HasNonAppLimitedSample = FALSE;

    Bbr->TotalBytesAcked = 0;
    Bbr->TotalBytesSent = 0;
    Bbr->TotalBytesLost = 0;

    Bbr->LastSendStateValid = FALSE;
    Bbr->LastSendStateAppLimited = FALSE;
    Bbr->LastSendStateInflight = 0;
    Bbr->LastSendStateTotalBytesAcked = 0;

    Bbr->CycleStartTime = 0;
    Bbr->PhaseStartTime = 0;
    Bbr->RoundsInPhase = 0;
    Bbr->RoundsSinceProbe = 0;
    Bbr->ProbeWaitTime = 0;
    Bbr->ProbeUpRounds = 0;
    Bbr->ProbeUpBytes = UINT64_MAX;
    Bbr->ProbeUpAcked = 0;
    Bbr->HasAdvancedMaxBw = FALSE;
    Bbr->IsSampleFromProbing = FALSE;
    Bbr->LastCycleProbedTooHigh = FALSE;
    Bbr->LastCycleStoppedRiskyProbe = FALSE;

    Bbr->ProbeRttExitTime = 0;
    Bbr->ProbeRttExitTimeValid = FALSE;

    Bbr->MaxAckHeightFilter = QuicSlidingWindowExtremumInitialize(
        kBbr3MaxAckHeightFilterLen,
        kBbr3DefaultFilterCapacity,
        Bbr->MaxAckHeightFilterEntries);
    Bbr->AckAggregationStartTime = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->AckAggregationStartTimeValid = FALSE;

    //
    // Bandwidth-sampler overestimate-avoidance state.
    //
    Bbr->RecentAckTime[0] = 0;
    Bbr->RecentAckTime[1] = 0;
    Bbr->RecentAckBytes[0] = 0;
    Bbr->RecentAckBytes[1] = 0;
    Bbr->A0CandHead = 0;
    Bbr->A0CandCount = 0;

    Bbr->LastAckTime = 0;
    Bbr->LastAckTimeValid = FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    QUIC_CONGESTION_CONTROL_BBR3* Bbr = &Cc->Bbr3;
    uint32_t SavedBytesInFlight = Bbr->BytesInFlight;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = Bbr->InitialCongestionWindowPackets;

    Bbr3CongestionControlInitialize(Cc, &Settings);

    if (!FullReset) {
        Bbr->BytesInFlight = SavedBytesInFlight;
    }
}
