/**
 * Hello message builder — constructs and sends the initial handshake payload.
 *
 * Sent on connect and whenever discovery data updates. Contains machine info,
 * registered directories, active/discovered sessions, available agents, and models.
 */

import type { Daemon } from '../core/daemon.js';
import type { AgentRegistry } from '../core/agent-registry.js';

const MAX_DISCOVERED_HELLO_SESSIONS = 1_000;

// ---------------------------------------------------------------------------
// Connected client interface (shared with ws-server)
// ---------------------------------------------------------------------------

export interface ConnectedClient {
  send: (data: string) => void;
  subscriptions: Set<string>;
  watchedDiscoveredSessions: Set<string>;
  /** Bytes queued for this client but not yet flushed by the kernel. */
  pendingBytes: number;
}

// ---------------------------------------------------------------------------
// Hello sender
// ---------------------------------------------------------------------------

export function sendHello(client: ConnectedClient, daemon: Daemon, registry?: AgentRegistry): void {
  const directories = daemon.directoryManager.list().map((d) => ({
    id: d.id,
    path: d.path,
    name: d.path.split('/').pop() ?? d.path,
  }));

  const activeSessions = daemon.getActiveSessions().map((id) => {
    const info = daemon.getSessionInfo(id);
    return { id, directoryId: info.directoryId, state: info.state };
  });

  // Include discovered sessions from JSONL files
  const discoveredSessions: Array<{
    id: string;
    agentId: string;
    directoryId: string;
    summary: string;
    lastActivity: number;
    messageCount: number;
    resumable: boolean;
  }> = [];

  for (const [directoryId, sessions] of daemon.getDiscoveredSessions()) {
    for (const s of sessions) {
      if (discoveredSessions.length >= MAX_DISCOVERED_HELLO_SESSIONS) break;
      discoveredSessions.push({
        id: s.sessionId,
        agentId: s.agentId,
        directoryId,
        summary: s.summary,
        lastActivity: s.lastModified,
        messageCount: s.messageCount ?? 0,
        resumable: s.resumable,
      });
    }
    if (discoveredSessions.length >= MAX_DISCOVERED_HELLO_SESSIONS) break;
  }

  // Rich agent info with capabilities (if registry available)
  const agents = registry
    ? registry.toHelloPayload()
    : daemon.getAvailableAgents().map((id) => ({
        id,
        displayName: id,
        tier: 'sdk' as const,
        available: true,
        capabilities: {
          structuredToolCalls: true,
          permissionCallbacks: true,
          tokenUsage: true,
          resume: true,
          extendedThinking: true,
        },
      }));

  // Include available models from agent SDKs (cached after first fetch)
  const models = registry ? registry.getCachedModels() : [];

  client.send(
    JSON.stringify({
      type: 'hello',
      protocolVersion: 2,
      machine: { id: daemon.configManager.getMachineId() },
      directories,
      activeSessions,
      discoveredSessions,
      discoveredSessionsTruncated: discoveredSessions.length >= MAX_DISCOVERED_HELLO_SESSIONS,
      availableAgents: daemon.getAvailableAgents(),
      agents,
      models,
    }),
  );
}
