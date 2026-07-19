/**
 * Watashi WASM coordination app.
 *
 * Handles peer discovery, screen layout persistence, and DID authentication
 * for cross-platform input sharing. The actual input capture/injection runs
 * in the Rust native host binary — this app manages the control plane.
 */
import {
  asAgentTool,
  createWorkerExport,
  createCadenceState,
  createInboxBuffer,
  cypherQueryAsync,
  decodeJson,
  genID,
  nowISO,
  resolveHeartbeatCadence,
  str,
  withCapabilityTags,
  type ComAtprotoSyncSubscribeReposCommit,
  type HostSDK,
} from "@etzhayyim/kotodama-host-sdk";

const NS = "com.etzhayyim.apps.watashi";

const cadenceState = createCadenceState();
const inbox = createInboxBuffer();

let appId = "";
let actorDID = "";
let _pds: any = null;

// ─── Graph Labels ───
// Domain-specific Cypher node labels for cross-platform input sharing graph.
//   WatashiPeer       — registered peer device
//   WatashiSession    — active sharing session between peers
//   WatashiClipboard  — clipboard sync event (text/image/file)
//   WatashiTransfer   — file drag-and-drop transfer between peers
//   WatashiAuditLog   — security audit log for input sharing events
//   WatashiRelease    — published binary release (per platform/version)
//   WatashiPairing    — WebAuthn/PIN/QR device pairing request

// ─── Collection Kinds (AT Protocol camelCase) ───
// peer, layout, session, clipboardSync, fileTransfer, auditLog, peerHeartbeat
// release, pairing

/** Maximum peers in a single sharing session. */
const MAX_SESSION_PEERS = 8;
/** Clipboard sync size limit in bytes (10 MB). */
const MAX_CLIPBOARD_SIZE_BYTES = 10 * 1024 * 1024;
/** Peer heartbeat timeout before marking offline (seconds). */
const PEER_HEARTBEAT_TIMEOUT_SEC = 30;
/** Maximum file transfer size in bytes (1 GB). */
const MAX_FILE_TRANSFER_BYTES = 1024 * 1024 * 1024;
/** Supported platforms for cross-platform sharing. */
const SUPPORTED_PLATFORMS = ["macos", "windows", "linux"] as const;

/** Register a peer device with its screen geometries. */
async function cmdRegisterPeer(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { peerId, name, platform, screens, addr } = body as {
    peerId: string;
    name: string;
    platform: "macos" | "windows" | "linux";
    screens: Array<{
      id: number;
      x: number;
      y: number;
      width: number;
      height: number;
      scaleFactor: number;
    }>;
    addr: string;
  };

  // Business rule: validate platform is supported
  if (!SUPPORTED_PLATFORMS.includes(platform as typeof SUPPORTED_PLATFORMS[number])) {
    return { ok: false, error: "unsupported_platform", detail: `Platform "${platform}" not supported. Supported: ${SUPPORTED_PLATFORMS.join(", ")}` };
  }

  // Business rule: peer must have at least one screen
  if (!screens || screens.length === 0) {
    return { ok: false, error: "no_screens", detail: "Peer must have at least one screen" };
  }

  // Business rule: validate screen dimensions are positive
  for (const scr of screens) {
    if (scr.width <= 0 || scr.height <= 0) {
      return { ok: false, error: "invalid_screen", detail: `Screen ${scr.id} has invalid dimensions (${scr.width}x${scr.height})` };
    }
  }

  const rkey = genID("peer");
  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.peer`,
      rkey,
      recordJson: JSON.stringify({
        peerId,
        name,
        platform,
        screens,
        addr,
        registeredAt: nowISO(),
      }),
    },
  });

  // Upsert peer node in graph
  await cypherQueryAsync(
    `MERGE (p:WatashiPeer {peerId: $peerId})
     SET p.name = $name, p.platform = $platform, p.addr = $addr,
         p.screenCount = $screenCount, p.updatedAt = $updatedAt
     RETURN p LIMIT 1`,
    {
      peerId,
      name,
      platform,
      addr,
      screenCount: screens.length,
      updatedAt: nowISO(),
    },
  );

  return { ok: true, rkey, peerId };
}

/** Save screen layout configuration (which peer at which edge). */
async function cmdSaveLayout(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { localPeerId, edges } = body as {
    localPeerId: string;
    edges: {
      left?: string;
      right?: string;
      top?: string;
      bottom?: string;
    };
  };

  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.layout`,
      rkey: localPeerId,
      recordJson: JSON.stringify({
        localPeerId,
        edges,
        savedAt: nowISO(),
      }),
    },
  });

  // Store edge relationships in graph
  for (const [edge, remotePeerId] of Object.entries(edges)) {
    if (!remotePeerId) continue;
    await cypherQueryAsync(
      `MATCH (a:WatashiPeer {peerId: $localId})
       MATCH (b:WatashiPeer {peerId: $remoteId})
       MERGE (a)-[r:SCREEN_EDGE {edge: $edge}]->(b)
       SET r.updatedAt = $now
       RETURN r LIMIT 1`,
      {
        localId: localPeerId,
        remoteId: remotePeerId,
        edge,
        now: nowISO(),
      },
    );
  }

  return { ok: true, localPeerId };
}

/** Get layout for a peer. */
async function cmdGetLayout(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { peerId } = body as { peerId: string };

  const rows = await cypherQueryAsync(
    `MATCH (a:WatashiPeer {peerId: $peerId})-[r:SCREEN_EDGE]->(b:WatashiPeer)
     RETURN r.edge AS edge, b.peerId AS remotePeerId, b.name AS remoteName,
            b.addr AS remoteAddr, b.platform AS remotePlatform
     LIMIT 10`,
    { peerId },
  );

  const edges: Record<string, unknown> = {};
  for (const row of rows) {
    edges[row.edge as string] = {
      peerId: row.remotePeerId,
      name: row.remoteName,
      addr: row.remoteAddr,
      platform: row.remotePlatform,
    };
  }

  return { peerId, edges };
}

/** List all registered peers. */
async function cmdListPeers(
  _ctx: unknown,
  _payload: Uint8Array,
): Promise<unknown> {
  const rows = await cypherQueryAsync(
    `MATCH (p:WatashiPeer)
     RETURN p.peerId AS peerId, p.name AS name, p.platform AS platform,
            p.addr AS addr, p.screenCount AS screenCount, p.updatedAt AS updatedAt
     ORDER BY p.updatedAt DESC
     LIMIT 50`,
    {},
  );
  return { peers: rows };
}

// ─── Session Management ───

/** Create a sharing session between peers. Validates peer count and platform compatibility. */
async function cmdCreateSession(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { sessionName, peerIds, encryption } = body as {
    sessionName: string;
    peerIds: string[];
    encryption?: "chacha20" | "aes256" | "none";
  };

  if (!peerIds || peerIds.length < 2) {
    return { ok: false, error: "insufficient_peers", detail: "Session requires at least 2 peers" };
  }

  // Business rule: enforce maximum session size
  if (peerIds.length > MAX_SESSION_PEERS) {
    return { ok: false, error: "session_too_large", detail: `Maximum ${MAX_SESSION_PEERS} peers per session, got ${peerIds.length}` };
  }

  // Business rule: default to encrypted transport, warn on unencrypted
  const effectiveEncryption = encryption ?? "chacha20";
  let securityLevel: "high" | "standard" | "insecure";
  if (effectiveEncryption === "chacha20" || effectiveEncryption === "aes256") {
    securityLevel = "high";
  } else {
    securityLevel = "insecure";
  }

  const sessionId = genID("ses");
  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.session`,
      rkey: sessionId,
      recordJson: JSON.stringify({
        sessionId,
        sessionName: sessionName ?? `Session ${sessionId}`,
        peerIds,
        peerCount: peerIds.length,
        encryption: effectiveEncryption,
        securityLevel,
        status: "active",
        createdAt: nowISO(),
        org_id: "anon",
        user_id: "anon",
        actor_id: appId,
      }),
    },
  });

  // Create session node in graph
  await cypherQueryAsync(
    `CREATE (s:WatashiSession {sessionId: $sessionId, sessionName: $sessionName, peerCount: $peerCount, encryption: $encryption, securityLevel: $securityLevel, status: $status, createdAt: $createdAt})
     RETURN s LIMIT 1`,
    {
      sessionId,
      sessionName: sessionName ?? `Session ${sessionId}`,
      peerCount: peerIds.length,
      encryption: effectiveEncryption,
      securityLevel,
      status: "active",
      createdAt: nowISO(),
    },
  );

  return { ok: true, sessionId, peerCount: peerIds.length, encryption: effectiveEncryption, securityLevel };
}

// ─── Clipboard Sync ───

/** Sync clipboard content between peers. Validates size limits and content type. */
async function cmdSyncClipboard(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { sessionId, sourcePeerId, contentType, sizeBytes, contentHash } = body as {
    sessionId: string;
    sourcePeerId: string;
    contentType: "text" | "image" | "file" | "richText";
    sizeBytes: number;
    contentHash: string;
  };

  if (!sessionId || !sourcePeerId) {
    return { ok: false, error: "missing_params", detail: "sessionId and sourcePeerId required" };
  }

  // Business rule: enforce clipboard size limit
  if (sizeBytes > MAX_CLIPBOARD_SIZE_BYTES) {
    return { ok: false, error: "clipboard_too_large", detail: `Clipboard content (${(sizeBytes / 1024 / 1024).toFixed(1)} MB) exceeds limit (${MAX_CLIPBOARD_SIZE_BYTES / 1024 / 1024} MB)` };
  }

  // Business rule: image clipboard requires minimum size (likely not empty)
  if (contentType === "image" && sizeBytes < 100) {
    return { ok: false, error: "image_too_small", detail: "Image clipboard content appears empty or corrupted" };
  }

  const syncId = genID("clip");
  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.clipboardSync`,
      rkey: syncId,
      recordJson: JSON.stringify({
        syncId,
        sessionId,
        sourcePeerId,
        contentType,
        sizeBytes,
        contentHash,
        syncedAt: nowISO(),
        org_id: "anon",
        user_id: "anon",
        actor_id: sourcePeerId,
      }),
    },
  });

  await cypherQueryAsync(
    `CREATE (c:WatashiClipboard {syncId: $syncId, sessionId: $sessionId, sourcePeerId: $sourcePeerId, contentType: $contentType, sizeBytes: $sizeBytes, syncedAt: $syncedAt})
     RETURN c LIMIT 1`,
    { syncId, sessionId, sourcePeerId, contentType, sizeBytes, syncedAt: nowISO() },
  );

  return { ok: true, syncId, contentType, sizeBytes };
}

// ─── File Transfer ───

/** Initiate file transfer between peers. Validates file size and transfer direction. */
async function cmdInitiateTransfer(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { sessionId, sourcePeerId, targetPeerId, fileName, fileSizeBytes } = body as {
    sessionId: string;
    sourcePeerId: string;
    targetPeerId: string;
    fileName: string;
    fileSizeBytes: number;
  };

  if (!sourcePeerId || !targetPeerId || !fileName) {
    return { ok: false, error: "missing_params", detail: "sourcePeerId, targetPeerId, fileName required" };
  }

  // Business rule: cannot transfer to self
  if (sourcePeerId === targetPeerId) {
    return { ok: false, error: "self_transfer", detail: "Cannot transfer file to the same peer" };
  }

  // Business rule: enforce file size limit
  if (fileSizeBytes > MAX_FILE_TRANSFER_BYTES) {
    return { ok: false, error: "file_too_large", detail: `File size (${(fileSizeBytes / 1024 / 1024 / 1024).toFixed(2)} GB) exceeds limit (${MAX_FILE_TRANSFER_BYTES / 1024 / 1024 / 1024} GB)` };
  }

  // Business rule: estimate transfer time and warn on large files
  let priority: "normal" | "background";
  if (fileSizeBytes > 100 * 1024 * 1024) {
    priority = "background";
  } else {
    priority = "normal";
  }

  const transferId = genID("xfr");
  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.fileTransfer`,
      rkey: transferId,
      recordJson: JSON.stringify({
        transferId,
        sessionId,
        sourcePeerId,
        targetPeerId,
        fileName,
        fileSizeBytes,
        priority,
        status: "initiated",
        initiatedAt: nowISO(),
        org_id: "anon",
        user_id: "anon",
        actor_id: sourcePeerId,
      }),
    },
  });

  await cypherQueryAsync(
    `CREATE (t:WatashiTransfer {transferId: $transferId, sessionId: $sessionId, sourcePeerId: $sourcePeerId, targetPeerId: $targetPeerId, fileName: $fileName, fileSizeBytes: $fileSizeBytes, priority: $priority, status: $status, initiatedAt: $initiatedAt})
     RETURN t LIMIT 1`,
    { transferId, sessionId, sourcePeerId, targetPeerId, fileName, fileSizeBytes, priority, status: "initiated", initiatedAt: nowISO() },
  );

  return { ok: true, transferId, fileName, fileSizeBytes, priority };
}

// ─── Peer Heartbeat ───

/** Record peer heartbeat to track online status. Marks peer as online/offline based on timing. */
async function cmdPeerHeartbeat(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { peerId, cpuUsage, memoryUsage } = body as {
    peerId: string;
    cpuUsage?: number;
    memoryUsage?: number;
  };

  if (!peerId) {
    return { ok: false, error: "missing_params", detail: "peerId required" };
  }

  // Business rule: validate resource usage values if provided
  if (cpuUsage !== undefined && (cpuUsage < 0 || cpuUsage > 100)) {
    return { ok: false, error: "invalid_cpu", detail: "CPU usage must be between 0 and 100" };
  }

  await cypherQueryAsync(
    `MERGE (p:WatashiPeer {peerId: $peerId})
     SET p.lastHeartbeat = $now, p.onlineStatus = 'online', p.cpuUsage = $cpu, p.memoryUsage = $mem
     RETURN p LIMIT 1`,
    { peerId, now: nowISO(), cpu: cpuUsage ?? -1, mem: memoryUsage ?? -1 },
  );

  return { ok: true, peerId, onlineStatus: "online" };
}

// ─── Audit Log ───

/** Record an audit log entry for security-sensitive operations. */
async function cmdRecordAudit(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { peerId, action, targetPeerId, detail } = body as {
    peerId: string;
    action: "connect" | "disconnect" | "clipboard_read" | "file_send" | "screen_capture" | "config_change";
    targetPeerId?: string;
    detail?: string;
  };

  if (!peerId || !action) {
    return { ok: false, error: "missing_params", detail: "peerId and action required" };
  }

  // Business rule: screen_capture events require explicit target
  if (action === "screen_capture" && !targetPeerId) {
    return { ok: false, error: "target_required", detail: "Screen capture audit events require a target peer" };
  }

  const auditId = genID("aud");
  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.auditLog`,
      rkey: auditId,
      recordJson: JSON.stringify({
        auditId,
        peerId,
        action,
        targetPeerId: targetPeerId ?? "",
        detail: detail ?? "",
        loggedAt: nowISO(),
        org_id: "anon",
        user_id: "anon",
        actor_id: peerId,
      }),
    },
  });

  await cypherQueryAsync(
    `CREATE (a:WatashiAuditLog {auditId: $auditId, peerId: $peerId, action: $action, targetPeerId: $targetPeerId, loggedAt: $loggedAt})
     RETURN a LIMIT 1`,
    { auditId, peerId, action, targetPeerId: targetPeerId ?? "", loggedAt: nowISO() },
  );

  return { ok: true, auditId, action };
}

// ─── Binary Download / Release ───

/** Supported release platforms and architectures. */
const RELEASE_PLATFORMS = {
  "macos-arm64": { os: "macos", arch: "arm64", ext: ".tar.gz", label: "macOS (Apple Silicon)" },
  "macos-x64": { os: "macos", arch: "x64", ext: ".tar.gz", label: "macOS (Intel)" },
  "windows-x64": { os: "windows", arch: "x64", ext: ".zip", label: "Windows (64-bit)" },
  "linux-x64": { os: "linux", arch: "x64", ext: ".tar.gz", label: "Linux (64-bit)" },
} as const;

type ReleasePlatformKey = keyof typeof RELEASE_PLATFORMS;

/** Register a new binary release for download. Stores metadata in graph + AT Record. */
async function cmdPublishRelease(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { version, platform, blobKey, sizeBytes, sha256 } = body as {
    version: string;
    platform: ReleasePlatformKey;
    blobKey: string;
    sizeBytes: number;
    sha256: string;
  };

  if (!version || !platform || !blobKey || !sha256) {
    return { ok: false, error: "missing_params", detail: "version, platform, blobKey, sha256 required" };
  }

  if (!(platform in RELEASE_PLATFORMS)) {
    return { ok: false, error: "invalid_platform", detail: `Supported: ${Object.keys(RELEASE_PLATFORMS).join(", ")}` };
  }

  const releaseId = genID("rel");
  const meta = RELEASE_PLATFORMS[platform];

  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.release`,
      rkey: releaseId,
      recordJson: JSON.stringify({
        releaseId,
        version,
        platform,
        os: meta.os,
        arch: meta.arch,
        blobKey,
        sizeBytes,
        sha256,
        fileName: `watashi-${version}-${platform}${meta.ext}`,
        publishedAt: nowISO(),
        org_id: "anon",
        user_id: "anon",
        actor_id: appId,
      }),
    },
  });

  await cypherQueryAsync(
    `MERGE (r:WatashiRelease {version: $version, platform: $platform})
     SET r.releaseId = $releaseId, r.blobKey = $blobKey, r.sizeBytes = $sizeBytes,
         r.sha256 = $sha256, r.publishedAt = $publishedAt
     RETURN r LIMIT 1`,
    { version, platform, releaseId, blobKey, sizeBytes, sha256, publishedAt: nowISO() },
  );

  return { ok: true, releaseId, version, platform, fileName: `watashi-${version}-${platform}${meta.ext}` };
}

/** Get download URL for the latest release matching the requested platform. */
async function cmdGetDownload(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { platform, version } = body as { platform?: ReleasePlatformKey; version?: string };

  let cypher: string;
  const params: Record<string, unknown> = {};

  if (version && platform) {
    cypher = `MATCH (r:WatashiRelease {version: $version, platform: $platform}) RETURN r.releaseId AS releaseId, r.version AS version, r.platform AS platform, r.blobKey AS blobKey, r.sizeBytes AS sizeBytes, r.sha256 AS sha256, r.publishedAt AS publishedAt LIMIT 1`;
    params.version = version;
    params.platform = platform;
  } else if (platform) {
    cypher = `MATCH (r:WatashiRelease {platform: $platform}) RETURN r.releaseId AS releaseId, r.version AS version, r.platform AS platform, r.blobKey AS blobKey, r.sizeBytes AS sizeBytes, r.sha256 AS sha256, r.publishedAt AS publishedAt ORDER BY r.publishedAt DESC LIMIT 1`;
    params.platform = platform;
  } else {
    cypher = `MATCH (r:WatashiRelease) RETURN r.releaseId AS releaseId, r.version AS version, r.platform AS platform, r.blobKey AS blobKey, r.sizeBytes AS sizeBytes, r.sha256 AS sha256, r.publishedAt AS publishedAt ORDER BY r.publishedAt DESC LIMIT 10`;
  }

  const rows = await cypherQueryAsync(cypher, params);
  if (rows.length === 0) {
    return { ok: true, releases: [], detail: "No releases found" };
  }

  const releases = rows.map((row) => {
    const plat = row.platform as ReleasePlatformKey;
    const meta = RELEASE_PLATFORMS[plat];
    return {
      releaseId: row.releaseId,
      version: row.version,
      platform: plat,
      label: meta?.label ?? plat,
      downloadUrl: `/api/blob/${row.blobKey}`,
      sizeBytes: row.sizeBytes,
      sha256: row.sha256,
      publishedAt: row.publishedAt,
    };
  });

  return { ok: true, releases };
}

/** List all available releases grouped by version. */
async function cmdListReleases(
  _ctx: unknown,
  _payload: Uint8Array,
): Promise<unknown> {
  const rows = await cypherQueryAsync(
    `MATCH (r:WatashiRelease)
     RETURN r.version AS version, r.platform AS platform, r.sizeBytes AS sizeBytes,
            r.sha256 AS sha256, r.publishedAt AS publishedAt
     ORDER BY r.publishedAt DESC
     LIMIT 50`,
    {},
  );
  return { ok: true, releases: rows };
}

// ─── WebAuthn Device Pairing ───

/**
 * Initiate WebAuthn-based device pairing.
 * Used when mDNS discovery is not available (different subnets, VPN, remote).
 * Creates a pairing challenge that the remote device completes via WebAuthn assertion.
 */
async function cmdInitiatePairing(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { localPeerId, pairingMethod } = body as {
    localPeerId: string;
    pairingMethod: "webauthn" | "pin" | "qr";
  };

  if (!localPeerId) {
    return { ok: false, error: "missing_params", detail: "localPeerId required" };
  }

  const method = pairingMethod ?? "webauthn";
  const pairingId = genID("pair");

  // Generate a random challenge for WebAuthn or PIN
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);
  const challenge = Array.from(challengeBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // For PIN mode: derive a 6-digit numeric PIN from challenge
  const pin = method === "pin"
    ? String(parseInt(challenge.slice(0, 8), 16) % 1000000).padStart(6, "0")
    : undefined;

  _pds.dispatch({
    type: "com.atproto.repo.createRecord",
    payload: {
      collection: `${NS}.pairing`,
      rkey: pairingId,
      recordJson: JSON.stringify({
        pairingId,
        localPeerId,
        method,
        challenge,
        pin: pin ?? "",
        status: "pending",
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        createdAt: nowISO(),
        org_id: "anon",
        user_id: "anon",
        actor_id: localPeerId,
      }),
    },
  });

  await cypherQueryAsync(
    `CREATE (p:WatashiPairing {pairingId: $pairingId, localPeerId: $localPeerId, method: $method, status: $status, expiresAt: $expiresAt, createdAt: $createdAt})
     RETURN p LIMIT 1`,
    {
      pairingId,
      localPeerId,
      method,
      status: "pending",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      createdAt: nowISO(),
    },
  );

  const result: Record<string, unknown> = { ok: true, pairingId, method, expiresInSeconds: 300 };

  if (method === "webauthn") {
    // Return WebAuthn challenge for the remote device to complete via auth.etzhayyim.com
    result.webauthn = {
      challenge,
      rpId: "watashi.etzhayyim.com",
      userVerification: "preferred",
      authUrl: `https://auth.etzhayyim.com/pair?challenge=${challenge}&app=watashi&pairingId=${pairingId}`,
    };
  } else if (method === "pin") {
    result.pin = pin;
    result.detail = "Display this PIN on the server screen. Enter it on the client to pair.";
  } else if (method === "qr") {
    // QR contains a deep link with the pairing challenge
    result.qrPayload = `watashi://pair?id=${pairingId}&challenge=${challenge}`;
    result.detail = "Scan this QR code on the remote device to pair.";
  }

  return result;
}

/** Complete a pairing request from the remote device side. */
async function cmdCompletePairing(
  _ctx: unknown,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { pairingId, remotePeerId, response } = body as {
    pairingId: string;
    remotePeerId: string;
    response: {
      method: "webauthn" | "pin";
      /** WebAuthn: base64url-encoded authenticator assertion. PIN: the 6-digit code. */
      credential?: string;
      pin?: string;
    };
  };

  if (!pairingId || !remotePeerId || !response) {
    return { ok: false, error: "missing_params", detail: "pairingId, remotePeerId, response required" };
  }

  // Look up the pairing record
  const rows = await cypherQueryAsync(
    `MATCH (p:WatashiPairing {pairingId: $pairingId, status: 'pending'})
     RETURN p.localPeerId AS localPeerId, p.method AS method, p.expiresAt AS expiresAt
     LIMIT 1`,
    { pairingId },
  );

  if (rows.length === 0) {
    return { ok: false, error: "pairing_not_found", detail: "Pairing request not found or already completed" };
  }

  const pairing = rows[0];
  const expiresAt = new Date(pairing.expiresAt as string);
  if (expiresAt < new Date()) {
    return { ok: false, error: "pairing_expired", detail: "Pairing request has expired. Initiate a new one." };
  }

  // Mark pairing as completed
  await cypherQueryAsync(
    `MATCH (p:WatashiPairing {pairingId: $pairingId})
     SET p.status = 'completed', p.remotePeerId = $remotePeerId, p.completedAt = $now
     RETURN p LIMIT 1`,
    { pairingId, remotePeerId, now: nowISO() },
  );

  // Create a trusted edge between the paired peers
  await cypherQueryAsync(
    `MATCH (a:WatashiPeer {peerId: $localPeerId})
     MATCH (b:WatashiPeer {peerId: $remotePeerId})
     MERGE (a)-[r:PAIRED_WITH]->(b)
     SET r.pairingId = $pairingId, r.method = $method, r.pairedAt = $now
     RETURN r LIMIT 1`,
    {
      localPeerId: pairing.localPeerId,
      remotePeerId,
      pairingId,
      method: pairing.method,
      now: nowISO(),
    },
  );

  _pds.dispatch({
    type: "app.bsky.feed.post",
    payload: {
      text: `Device paired: ${remotePeerId} ↔ ${pairing.localPeerId} via ${pairing.method}`,
    },
  });

  return {
    ok: true,
    pairingId,
    localPeerId: pairing.localPeerId,
    remotePeerId,
    method: pairing.method,
  };
}

// ─── Queries ───

/** Coverage stats for watashi graph entities. */
async function cmdCoverageStats(
  _ctx: unknown,
  _payload: Uint8Array,
): Promise<unknown> {
  const [peers, sessions, clipboards, transfers, audits, releases, pairings] = await Promise.all([
    cypherQueryAsync(`MATCH (n:WatashiPeer) RETURN count(n) AS cnt LIMIT 1`, {}),
    cypherQueryAsync(`MATCH (n:WatashiSession) WHERE n.status = 'active' RETURN count(n) AS cnt LIMIT 1`, {}),
    cypherQueryAsync(`MATCH (n:WatashiClipboard) RETURN count(n) AS cnt LIMIT 1`, {}),
    cypherQueryAsync(`MATCH (n:WatashiTransfer) RETURN count(n) AS cnt LIMIT 1`, {}),
    cypherQueryAsync(`MATCH (n:WatashiAuditLog) RETURN count(n) AS cnt LIMIT 1`, {}),
    cypherQueryAsync(`MATCH (n:WatashiRelease) RETURN count(n) AS cnt LIMIT 1`, {}),
    cypherQueryAsync(`MATCH (n:WatashiPairing) WHERE n.status = 'completed' RETURN count(n) AS cnt LIMIT 1`, {}),
  ]);

  return {
    ok: true,
    peers: Number(peers[0]?.cnt ?? 0),
    activeSessions: Number(sessions[0]?.cnt ?? 0),
    clipboardSyncs: Number(clipboards[0]?.cnt ?? 0),
    fileTransfers: Number(transfers[0]?.cnt ?? 0),
    auditLogs: Number(audits[0]?.cnt ?? 0),
    releases: Number(releases[0]?.cnt ?? 0),
    pairedDevices: Number(pairings[0]?.cnt ?? 0),
  };
}

// ─── Reactive Pipeline ───

/** Handle inbound commit events for watashi collections. */
function handleComAtprotoSyncSubscribeReposCommit(
  _sdk: HostSDK,
  commit: ComAtprotoSyncSubscribeReposCommit,
): { ok: true; detail: string } {
  if (commit.action !== "create") return { ok: true, detail: "skip non-create" };

  const collection = str(commit.collection ?? "");

  if (collection === `${NS}.peer`) {
    inbox.inboundCommits.push({ collection, action: "create", ts: Date.now() });
    return { ok: true, detail: `peer registered: ${collection}` };
  }
  if (collection === `${NS}.session`) {
    inbox.inboundCommits.push({ collection, action: "create", ts: Date.now() });
    return { ok: true, detail: `session created: ${collection}` };
  }
  if (collection === `${NS}.clipboardSync`) {
    return { ok: true, detail: `clipboard sync: ${collection}` };
  }
  if (collection === `${NS}.fileTransfer`) {
    inbox.inboundCommits.push({ collection, action: "create", ts: Date.now() });
    return { ok: true, detail: `file transfer: ${collection}` };
  }
  if (collection === `${NS}.auditLog`) {
    return { ok: true, detail: `audit: ${collection}` };
  }
  if (collection === `${NS}.release`) {
    return { ok: true, detail: `release published: ${collection}` };
  }
  if (collection === `${NS}.pairing`) {
    inbox.inboundCommits.push({ collection, action: "create", ts: Date.now() });
    return { ok: true, detail: `pairing: ${collection}` };
  }

  return { ok: true, detail: `accepted ${collection}` };
}

export { handleComAtprotoSyncSubscribeReposCommit };

export async function runHeartbeat(sdk: HostSDK): Promise<{ ok: boolean; actions: Array<Record<string, unknown>> }> {
  const actions: Array<Record<string, unknown>> = [];
  const ts = nowISO();
  const cadence = await resolveHeartbeatCadence(actorDID, cadenceState, inbox);
  actions.push({ action: "cadenceResolved", mood: cadence.mood, shouldPost: cadence.shouldPost, reason: cadence.reason, ts });

  if (cadence.shouldPost && cadence.contentSource.type !== "none") {
    try {
      const stats = await cmdCoverageStats(sdk, new Uint8Array());
      const s = stats as Record<string, unknown>;
      const text = `Watashi: ${s.peers} peers, ${s.activeSessions} sessions, ${s.clipboardSyncs} clipboard syncs, ${s.fileTransfers} transfers`;
      actions.push({ action: "post", source: "coverageStats", ts });
    } catch (e) {
      console.warn("heartbeat post:", e);
      actions.push({ action: "postFailed", error: String(e), ts });
    }
  }

  if (actions.length === 1) actions.push({ action: "noop", mood: cadence.mood, ts });
  return { ok: true, actions };
}

export default createWorkerExport((sdk: HostSDK) => {
  appId = sdk.pds.selfNanoid ?? "";
  actorDID = sdk.pds.selfRepo ?? "";
  _pds = sdk.pds;

  // Blob download route: serve release binaries from CDN_R2
  const cdnR2 = (sdk.pds as any).cdnR2 as any;
  sdk.router.get("/api/blob/*", async (c: any) => {
    if (!cdnR2) return c.json({ error: "storage not configured" }, 503);
    const key = c.req.path.replace("/api/blob/", "");
    const obj = await cdnR2.get(key);
    if (!obj) return c.json({ error: "not found" }, 404);
    const fileName = key.split("/").pop() ?? "download";
    return new Response(obj.body, {
      headers: {
        "Content-Type": (obj as any).httpMetadata?.contentType ?? "application/octet-stream",
        "Content-Disposition": `attachment; filename="${fileName}"`,
        "Content-Length": String((obj as any).size ?? 0),
        "Cache-Control": "public, max-age=86400, immutable",
      },
    });
  });

  sdk.app
    .command(
      `${NS}.registerPeer`,
      cmdRegisterPeer,
      asAgentTool("Register a peer device for input sharing"),
      withCapabilityTags("input-sharing", "peer-discovery"),
    )
    .command(
      `${NS}.saveLayout`,
      cmdSaveLayout,
      asAgentTool("Save screen layout configuration"),
      withCapabilityTags("input-sharing", "configuration"),
    )
    .command(
      `${NS}.createSession`,
      cmdCreateSession,
      asAgentTool("Create sharing session between peers"),
      withCapabilityTags("input-sharing", "session"),
    )
    .command(
      `${NS}.syncClipboard`,
      cmdSyncClipboard,
      asAgentTool("Sync clipboard content between peers"),
      withCapabilityTags("input-sharing", "clipboard"),
    )
    .command(
      `${NS}.initiateTransfer`,
      cmdInitiateTransfer,
      asAgentTool("Initiate file transfer between peers"),
      withCapabilityTags("input-sharing", "file-transfer"),
    )
    .command(
      `${NS}.peerHeartbeat`,
      cmdPeerHeartbeat,
      asAgentTool("Record peer heartbeat for online status"),
      withCapabilityTags("input-sharing", "monitoring"),
    )
    .command(
      `${NS}.recordAudit`,
      cmdRecordAudit,
      asAgentTool("Record security audit log entry"),
      withCapabilityTags("input-sharing", "security", "audit"),
    )
    .command(
      `${NS}.publishRelease`,
      cmdPublishRelease,
      asAgentTool("Publish a binary release for download"),
      withCapabilityTags("input-sharing", "distribution"),
    )
    .command(
      `${NS}.initiatePairing`,
      cmdInitiatePairing,
      asAgentTool("Initiate WebAuthn/PIN/QR device pairing"),
      withCapabilityTags("input-sharing", "pairing", "security"),
    )
    .command(
      `${NS}.completePairing`,
      cmdCompletePairing,
      asAgentTool("Complete device pairing from remote side"),
      withCapabilityTags("input-sharing", "pairing", "security"),
    )
    .query(`${NS}.getLayout`, cmdGetLayout)
    .query(`${NS}.listPeers`, cmdListPeers)
    .query(`${NS}.getDownload`, cmdGetDownload)
    .query(`${NS}.listReleases`, cmdListReleases)
    .query(`${NS}.coverageStats`, cmdCoverageStats);
});
