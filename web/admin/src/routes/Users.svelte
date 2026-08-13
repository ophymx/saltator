<script lang="ts">
  import * as api from '../lib/api';
  import { handle } from '../lib/session.svelte';
  import { href, link } from '../lib/router.svelte';
  import { ts } from '../lib/format';

  const LIMIT = 50;

  let users = $state<api.UserSummary[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  // The API pages forward by start key. Keeping the keys we have visited
  // is what makes "previous" possible without a backwards cursor.
  let cursors = $state<(string | null)[]>([null]);
  let page = $state(0);
  let nextFrom = $state<string | null>(null);

  // Takes its cursor as an argument rather than reading state, so the
  // effect below is the only thing that decides when a load happens —
  // paging just moves the cursor.
  async function load(from: string | null) {
    loading = true;
    error = null;
    try {
      const result = await api.listUsers(from, LIMIT);
      users = result.users;
      nextFrom = result.next_from ?? null;
    } catch (e) {
      error = handle(e);
    } finally {
      loading = false;
    }
  }

  function next() {
    if (nextFrom === null) return;
    if (page + 1 >= cursors.length) cursors.push(nextFrom);
    page += 1;
  }

  function previous() {
    if (page > 0) page -= 1;
  }

  $effect(() => {
    void load(cursors[page] ?? null);
  });
</script>

<div class="spread">
  <div>
    <h1>Users</h1>
    <p class="sub">Every account on this server, in user-id order.</p>
  </div>
</div>

{#if error}<div class="notice error">{error}</div>{/if}

<table>
  <thead>
    <tr>
      <th>User</th>
      <th>State</th>
      <th>Role</th>
      <th class="right">Created</th>
    </tr>
  </thead>
  <tbody>
    {#each users as user (user.user_id)}
      <tr>
        <td>
          <a class="mono" href={href(`/users/${encodeURIComponent(user.user_id)}`)} onclick={link}>
            {user.user_id}
          </a>
          {#if user.displayname}<span class="muted small"> · {user.displayname}</span>{/if}
        </td>
        <td>
          <span
            class="badge"
            class:ok={user.state === 'active'}
            class:warn={user.state === 'locked'}
            class:danger={user.state === 'deactivated'}>{user.state}</span
          >
          {#if user.erased}<span class="badge danger">erased</span>{/if}
        </td>
        <td>{#if user.admin}<span class="badge">admin</span>{/if}</td>
        <td class="right muted small">{ts(user.created_ts)}</td>
      </tr>
    {:else}
      <tr><td colspan="4" class="empty">{loading ? 'Loading…' : 'No accounts.'}</td></tr>
    {/each}
  </tbody>
</table>

<div class="row" style="margin-top:1rem; justify-content:flex-end">
  <span class="muted small">Page {page + 1}</span>
  <button onclick={previous} disabled={page === 0 || loading}>Previous</button>
  <button onclick={next} disabled={nextFrom === null || loading}>Next</button>
</div>
