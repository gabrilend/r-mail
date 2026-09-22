package com.rmail.app.sync

import kotlin.random.Random

/**
 * Progressive sync backoff, mirroring the daemon's `ctimer` (#377).
 *
 * The phone used to poll on a fixed 10s timer — a testing value that was
 * never reverted. That is wrong in both directions: far too chatty against a
 * server that has nothing to say, and no slower at all against one that is
 * unreachable, so a phone off-network retried every 10 seconds indefinitely.
 *
 * The values deliberately match the daemon's, because the two sides are
 * solving the same problem and there is no reason for them to disagree:
 * floor 30s, additive +360s per failure, 2h ceiling, ±30s of jitter on every
 * due time.
 *
 * Growth is additive rather than multiplicative, and recovery is immediate
 * rather than gradual. One success proves the server is reachable *now*,
 * which makes accumulated evidence of unreachability worthless — there is
 * nothing to decay slowly. Slow to distrust, quick to forgive.
 *
 * The jitter matters more here than it looks. Without it, a phone that
 * failed alongside other clients (a router reboot, an ISP blip) would retry
 * in lockstep with them forever, re-creating the thundering herd on every
 * step. ±30s is enough to break that up.
 *
 * This governs *polling only*. A local write still syncs immediately — see
 * `MainViewModel.triggerSync`. Backoff answers "how long until we check
 * again when nothing has happened", never "how long before we send what the
 * user just wrote".
 */
class SyncBackoff(
    private val floorMs: Long = 30_000L,
    private val stepMs: Long = 360_000L,
    private val ceilingMs: Long = 7_200_000L,
    private val jitterMs: Long = 30_000L,
    private val now: () -> Long = System::currentTimeMillis,
) {
    /** Current backoff interval, before jitter. */
    var intervalMs: Long = floorMs
        private set

    /** Epoch millis at which a poll is next allowed. 0 = due immediately. */
    var nextDueAt: Long = 0L
        private set

    /** Timestamp of the last successful sync, or null if there has not been one. */
    var lastSuccessAt: Long? = null
        private set

    private fun jittered(base: Long): Long {
        // nextLong is exclusive on the upper bound, so +1 keeps the range
        // symmetric: [-jitter, +jitter] rather than [-jitter, +jitter).
        val offset = Random.nextLong(-jitterMs, jitterMs + 1)
        // Never let jitter pull a due time into the past; a floor-length
        // interval with -30s of jitter would otherwise be due immediately.
        return (base + offset).coerceAtLeast(1_000L)
    }

    /** A sync succeeded: drop straight back to the floor. */
    fun onSuccess() {
        val t = now()
        intervalMs = floorMs
        lastSuccessAt = t
        nextDueAt = t + jittered(floorMs)
    }

    /** A sync failed: step the interval up, capped at the ceiling. */
    fun onFailure() {
        val t = now()
        intervalMs = (intervalMs + stepMs).coerceAtMost(ceilingMs)
        nextDueAt = t + jittered(intervalMs)
    }

    /**
     * Something happened that proves the server is worth talking to right
     * now — new mail arrived, the user wrote something, the app came back to
     * the foreground. Equivalent to the daemon's `ctimer.saw_inbound`.
     */
    fun resetNow() {
        intervalMs = floorMs
        nextDueAt = 0L
    }

    /** Milliseconds until the next poll is due; 0 when it is due now. */
    fun timeUntilDue(): Long = (nextDueAt - now()).coerceAtLeast(0L)

    fun isDue(): Boolean = now() >= nextDueAt

    /** For display/debugging: the current interval in whole seconds. */
    fun intervalSeconds(): Long = intervalMs / 1000
}
