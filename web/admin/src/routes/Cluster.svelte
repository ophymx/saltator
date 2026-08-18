<script lang="ts">
  import * as api from '../lib/api';
  import { handle } from '../lib/session.svelte';

  let list = $state<api.NodeList | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let reloads = $state(0);

  async function load() {
    error = null;
    try {
      list = await api.listNodes();
    } catch (e) {
      error = handle(e);
    }
  }

  async function run(call: () => Promise<api.NodeList>) {
    busy = true;
    error = null;
    try {
      list = await call();
    } catch (e) {
      error = handle(e);
    } finally {
      busy = false;
    }
  }

  function remove(node: api.ClusterNode) {
    if (
      !window.confirm(
        `Remove node ${node.node_id} from the cluster?\n\n` +
          'Do this only after the node has finished draining and its process ' +
          'has been stopped.',
      )
    )
      return;
    run(() => api.removeNode(node.node_id));
  }

  $effect(() => {
    void reloads;
    void load();
  });
</script>

<div class="spread">
  <div>
    <h1>Cluster</h1>
    <p class="sub">
      {#if list}Roster as node {list.view_from} sees it{#if list.leader !== null}, leader is node
          {list.leader}{/if}.{/if}
    </p>
  </div>
  <button onclick={() => (reloads += 1)} disabled={busy}>Refresh</button>
</div>

{#if error}<div class="notice error">{error}</div>{/if}

<div class="notice">
  <strong>Draining is half the job.</strong> A drained node stops hosting
  replicas but keeps running with state that no longer updates, so it must be
  taken out of the load balancer and stopped. The sequence is: drain, wait until
  its groups are empty, stop the process, then remove.
</div>

<table>
  <thead>
    <tr>
      <th>Node</th>
      <th>Address</th>
      <th>Status</th>
      <th>Hosts</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {#each list?.nodes ?? [] as node (node.node_id)}
      <tr>
        <td>
          {node.node_id}
          {#if list && node.node_id === list.leader}<span class="badge">leader</span>{/if}
          {#if list && node.node_id === list.view_from}<span class="badge">this node</span>{/if}
        </td>
        <td class="mono small">{node.advertise_addr}</td>
        <td>
          <span class="badge" class:ok={node.status === 'active'} class:warn={node.status === 'draining'}>
            {node.status}
          </span>
          {#if !node.metadata_voter}<span class="badge warn">not a voter</span>{/if}
        </td>
        <td class="mono small">
          {#if node.groups.length === 0}
            <span class="muted">nothing — safe to stop</span>
          {:else}
            {node.groups.join(', ')}
          {/if}
        </td>
        <td class="right">
          {#if node.status === 'draining'}
            <button class="link" disabled={busy} onclick={() => run(() => api.drainNode(node.node_id, false))}>
              Return to service
            </button>
            <button class="link danger" disabled={busy} onclick={() => remove(node)}>Remove</button>
          {:else}
            <button class="link" disabled={busy} onclick={() => run(() => api.drainNode(node.node_id, true))}>
              Drain
            </button>
          {/if}
        </td>
      </tr>
    {:else}
      <tr><td colspan="5" class="empty">No cluster control plane.</td></tr>
    {/each}
  </tbody>
</table>
