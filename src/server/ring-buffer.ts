/**
 * Ring buffer for session update replay on reconnect.
 *
 * Each session gets its own buffer that stores the most recent N updates
 * with monotonically increasing sequence numbers. Clients that reconnect
 * can request replay from their last-seen seq to catch up.
 *
 * Uses index-based circular buffer for O(1) push (no array shifting).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SessionUpdateEntry {
  seq: number;
  sessionId: string;
  update: Record<string, unknown>;
}

export interface ReplayWindow {
  entries: SessionUpdateEntry[];
  droppedWindow: boolean;
  requestedLastSeq: number;
  earliestAvailableSeq: number;
  latestAvailableSeq: number;
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

export class RingBuffer {
  private buffer: (SessionUpdateEntry | null)[];
  private writeIndex = 0;
  private count = 0;
  private seq = 0;
  private readonly maxSize: number;

  constructor(maxSize = 500) {
    this.maxSize = maxSize;
    this.buffer = new Array(maxSize).fill(null);
  }

  push(sessionId: string, update: Record<string, unknown>): SessionUpdateEntry {
    this.seq++;
    const entry: SessionUpdateEntry = { seq: this.seq, sessionId, update };

    this.buffer[this.writeIndex] = entry;
    this.writeIndex = (this.writeIndex + 1) % this.maxSize;
    if (this.count < this.maxSize) this.count++;

    return entry;
  }

  getReplayWindow(lastSeq: number): ReplayWindow {
    const requestedLastSeq = Math.max(0, lastSeq);
    const entries = this.getAll();
    const earliestAvailableSeq = entries[0]?.seq ?? 0;
    const latestAvailableSeq = entries[entries.length - 1]?.seq ?? 0;

    const droppedWindow =
      requestedLastSeq > 0 &&
      earliestAvailableSeq > 0 &&
      requestedLastSeq < earliestAvailableSeq - 1;

    if (entries.length === 0) {
      return {
        entries: [],
        droppedWindow: false,
        requestedLastSeq,
        earliestAvailableSeq: 0,
        latestAvailableSeq: 0,
      };
    }

    const effectiveLastSeq = droppedWindow ? earliestAvailableSeq - 1 : requestedLastSeq;
    return {
      entries: this.getAfter(effectiveLastSeq),
      droppedWindow,
      requestedLastSeq,
      earliestAvailableSeq,
      latestAvailableSeq,
    };
  }

  getAfter(lastSeq: number): SessionUpdateEntry[] {
    const result: SessionUpdateEntry[] = [];
    // Read in order from oldest to newest
    for (let i = 0; i < this.count; i++) {
      const idx = (this.writeIndex - this.count + i + this.maxSize) % this.maxSize;
      const entry = this.buffer[idx]!;
      if (entry.seq > lastSeq) result.push(entry);
    }
    return result;
  }

  getAll(): SessionUpdateEntry[] {
    return this.getAfter(0);
  }
}
