/**
 * ShareMouse WASM coordination app.
 *
 * Handles peer discovery, screen layout persistence, and DID authentication
 * for cross-platform input sharing. The actual input capture/injection runs
 * in the Rust native host binary — this app manages the control plane.
 */
import {
  asAgentTool,
  createWorkerExport,
  cypherQueryAsync,
  genID,
  nowISO,
  withCapabilityTags,
  type HostSDK,
} from "@etzhayyim/kotodama-host-sdk";

const NS = "com.etzhayyim.apps.sharemouse";

/** Register a peer device with its screen geometries. */
async function cmdRegisterPeer(
  sdk: HostSDK,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { peerId, name, platform, screens, addr } = body as {
    peerId: string;
    name: string;
    platform: "macos" | "windows";
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

  const rkey = genID("peer");
  sdk.pds.dispatch({
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
    `MERGE (p:ShareMousePeer {peerId: $peerId})
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
  sdk: HostSDK,
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

  sdk.pds.dispatch({
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
      `MATCH (a:ShareMousePeer {peerId: $localId})
       MATCH (b:ShareMousePeer {peerId: $remoteId})
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
  _sdk: HostSDK,
  payload: Uint8Array,
): Promise<unknown> {
  const body = JSON.parse(new TextDecoder().decode(payload));
  const { peerId } = body as { peerId: string };

  const rows = await cypherQueryAsync(
    `MATCH (a:ShareMousePeer {peerId: $peerId})-[r:SCREEN_EDGE]->(b:ShareMousePeer)
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
  _sdk: HostSDK,
  _payload: Uint8Array,
): Promise<unknown> {
  const rows = await cypherQueryAsync(
    `MATCH (p:ShareMousePeer)
     RETURN p.peerId AS peerId, p.name AS name, p.platform AS platform,
            p.addr AS addr, p.screenCount AS screenCount, p.updatedAt AS updatedAt
     ORDER BY p.updatedAt DESC
     LIMIT 50`,
    {},
  );
  return { peers: rows };
}

export default createWorkerExport((sdk: HostSDK) => {
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
    .query(`${NS}.getLayout`, cmdGetLayout)
    .query(`${NS}.listPeers`, cmdListPeers);
});
