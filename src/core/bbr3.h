/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    BBRv3 congestion control. Pure-C port of Google QUICHE's bbr2_* (which
    implements BBRv3 behaviour under default parameters), adapted to msquic's
    aggregate ack/loss event model and integer fixed-point math (no floating
    point, so this also builds for the Windows kernel driver).

    Reference: quiche/quic/core/congestion_control/bbr2_*.{h,cc}

--*/

#pragma once

#include "sliding_window_extremum.h"

#define kBbr3DefaultFilterCapacity 3

//
// Capacity of the bandwidth sampler's a0-candidate ring (overestimate
// avoidance). One entry is produced per ack-aggregation epoch boundary and a
// handful are ever live at once, so this small fixed ring (no allocation,
// kernel-safe) is plenty; push drops the oldest if it ever fills.
//
#define BBR3_A0_CANDIDATES_MAX 16

//
// BBRv3 top-level mode (quic::Bbr2Mode).
//
typedef enum BBR3_MODE {
    BBR3_MODE_STARTUP,
    BBR3_MODE_DRAIN,
    BBR3_MODE_PROBE_BW,
    BBR3_MODE_PROBE_RTT
} BBR3_MODE;

//
// PROBE_BW sub-phase (quic::ProbePhase).
//
typedef enum BBR3_PROBE_PHASE {
    BBR3_PROBE_NOT_STARTED,
    BBR3_PROBE_UP,
    BBR3_PROBE_DOWN,
    BBR3_PROBE_CRUISE,
    BBR3_PROBE_REFILL
} BBR3_PROBE_PHASE;

typedef struct QUIC_CONGESTION_CONTROL_BBR3 {

    //
    // Current top-level mode and PROBE_BW sub-phase.
    //
    uint8_t BbrMode;    // BBR3_MODE
    uint8_t ProbePhase; // BBR3_PROBE_PHASE

    //
    // Boolean flags (bitfields packed together).
    //
    BOOLEAN MinRttTimestampValid : 1;
    BOOLEAN FullBandwidthReached : 1;
    BOOLEAN HasNonAppLimitedSample : 1;
    BOOLEAN AppLimited : 1;
    BOOLEAN InflightHiLimitedInRound : 1;
    BOOLEAN EndOfRoundTripValid : 1;
    BOOLEAN LastSentPacketValid : 1;
    BOOLEAN AckAggregationStartTimeValid : 1;

    BOOLEAN LastSendStateValid : 1;
    BOOLEAN LastSendStateAppLimited : 1;
    BOOLEAN HasAdvancedMaxBw : 1;
    BOOLEAN IsSampleFromProbing : 1;
    BOOLEAN LastCycleProbedTooHigh : 1;
    BOOLEAN LastCycleStoppedRiskyProbe : 1;
    BOOLEAN ProbeRttExitTimeValid : 1;
    BOOLEAN EcnRecoveryValid : 1; // an ECN-CE backoff has been recorded
    BOOLEAN LastAckTimeValid : 1; // a prior ack time is recorded (restart-from-idle)

    //
    // Congestion window state (bytes).
    //
    uint32_t InitialCongestionWindowPackets;
    uint32_t CongestionWindow;        // cwnd_
    uint32_t InitialCongestionWindow;
    uint32_t MinimumCongestionWindow; // cwnd_limits.Min()

    uint32_t BytesInFlight;
    uint32_t BytesInFlightMax;

    //
    // Probe packets allowed to ignore the congestion window.
    //
    uint8_t Exemptions;

    //
    // Pacing rate, in (bytes/sec * BW_UNIT) to match the bandwidth filter.
    //
    uint64_t PacingRate;

    //
    // Dynamic gains, in units of (1 / GAIN_UNIT).
    //
    uint32_t CwndGain;
    uint32_t PacingGain;

    //
    // Round-trip counter (quic::RoundTripCounter).
    //
    uint64_t RoundTripCount;
    uint64_t LastSentPacketNumber;
    uint64_t EndOfRoundTrip;

    //
    // Largest sent packet number at the last ECN-CE backoff, used to apply at
    // most one ECN backoff per round (quic/cubic RecoverySentPacketNumber).
    //
    uint64_t EcnRecoverySentPacketNumber;

    //
    // Two-slot max bandwidth filter (quic::Bbr2MaxBandwidthFilter); each slot
    // holds a delivery-rate sample scaled by BW_UNIT. Advanced once per cycle.
    //
    uint64_t MaxBandwidth[2];

    //
    // Min RTT filter.
    //
    uint64_t MinRtt;          // microseconds
    uint64_t MinRttTimestamp; // microseconds

    //
    // Short/long-term bandwidth and inflight bounds. *_Lo/*_Hi defaults are the
    // "infinite"/max sentinels (UINT64_MAX / UINT32_MAX).
    //
    uint64_t BandwidthLatest; // bytes/sec * BW_UNIT
    uint64_t BandwidthLo;     // bytes/sec * BW_UNIT, UINT64_MAX == unset
    uint64_t InflightLatest;  // bytes
    uint64_t InflightLo;      // bytes, UINT64_MAX == unset
    uint64_t InflightHi;      // bytes, UINT64_MAX == unset

    //
    // Per-round accumulators (reset by OnNewRound).
    //
    uint64_t BytesLostInRound;
    //
    // Loss buffered by OnDataLost, awaiting the next OnDataAcknowledged to be
    // folded into a single congestion event.
    //
    uint64_t BytesLostInRoundPending;
    uint64_t LossEventsInRound;
    uint64_t MaxBytesDeliveredInRound;
    uint64_t MinBytesInFlightInRound;

    //
    // STARTUP full-bandwidth detection.
    //
    uint64_t FullBandwidthBaseline; // bytes/sec * BW_UNIT
    uint64_t RoundsWithoutBandwidthGrowth;

    //
    // App-limited tracking (delegated bandwidth sampler state).
    //
    uint64_t AppLimitedExitTarget;

    //
    // Totals tracked across the connection's lifetime.
    //
    uint64_t TotalBytesAcked;
    uint64_t TotalBytesSent;
    uint64_t TotalBytesLost;

    //
    // Send-state of the largest packet in the current congestion event, used by
    // IsInflightTooHigh / MaybeAdaptUpperBounds.
    //
    uint64_t LastSendStateInflight;       // BytesInFlight(send_state)
    uint64_t LastSendStateTotalBytesAcked;

    //
    // PROBE_BW cycle state (quic::Bbr2ProbeBwMode::Cycle).
    //
    uint64_t CycleStartTime;  // microseconds
    uint64_t PhaseStartTime;  // microseconds
    uint64_t RoundsInPhase;
    uint64_t RoundsSinceProbe;
    uint64_t ProbeWaitTime;   // microseconds
    uint64_t ProbeUpRounds;
    uint64_t ProbeUpBytes;    // UINT64_MAX == unset
    uint64_t ProbeUpAcked;

    //
    // PROBE_RTT exit time.
    //
    uint64_t ProbeRttExitTime; // microseconds

    //
    // Ack-aggregation ("extra acked") tracking, reused from msquic BBRv1.
    //
    QUIC_SLIDING_WINDOW_EXTREMUM MaxAckHeightFilter;
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY MaxAckHeightFilterEntries[kBbr3DefaultFilterCapacity];
    uint64_t AckAggregationStartTime; // microseconds
    uint64_t AggregatedAckBytes;

    //
    // Bandwidth-sampler "overestimate avoidance" state (quic BSAO). The ack-rate
    // sample's A0 baseline is anchored to an earlier ack-aggregation-epoch
    // boundary (a "quiet" point) instead of "the most recent ack at send time",
    // so a burst of aggregated acks cannot inflate the delivery-rate sample. See
    // the sampler in Bbr3OnCongestionEventStart.
    //
    // RecentAckPoints: the two most recent ack points at distinct times
    // (quic::BandwidthSampler::RecentAckPoints): [0] = less recent, [1] = recent.
    //
    uint64_t RecentAckTime[2];  // microseconds
    uint64_t RecentAckBytes[2]; // total bytes acked
    //
    // a0_candidates ring buffer of quiet-point ack references from past epochs.
    //
    uint64_t A0CandTime[BBR3_A0_CANDIDATES_MAX];  // microseconds
    uint64_t A0CandBytes[BBR3_A0_CANDIDATES_MAX]; // total bytes acked
    uint32_t A0CandHead;
    uint32_t A0CandCount;

    //
    // Restart-from-idle: time of the most recently processed ack. A gap larger
    // than the restart threshold marks a delivery stall (a bad-link "dead
    // window"); the next ack then re-enters STARTUP. See bbr3.c.
    //
    uint64_t LastAckTime; // microseconds

} QUIC_CONGESTION_CONTROL_BBR3;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
Bbr3CongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );
