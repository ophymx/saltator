<script lang="ts">
  import * as api from '../lib/api';
  import { handle } from '../lib/session.svelte';
  import { ts } from '../lib/format';

  const LIMIT = 50;

  let rooms = $state<api.RoomRow[]>([]);
  let blocked = $state<api.BlockedRoom[]>([]);
  let error = $state<string | null>(null);
  let report = $state<api.ShutdownReport | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let cursors = $state<(string | null)[]>([null]);
  let page = $state(0);
  let nextFrom = $state<string | null>(null);
  let reloads = $state(0);
  let blockRoomId = $state('');

  async function load(from: string | null) {
    loading = true;
    error = null;
    try {
      const [list, blockedList] = await Promise.all([
        api.listRooms(from, LIMIT),
        api.listBlockedRooms(),
      ]);
      rooms = list.rooms;
      nextFrom = list.next_from ?? null;
      blocked = blockedList.blocked_rooms;
    } catch (e) {
      error = handle(e);
    } finally {
      loading = false;
    }
  }

  async function run(call: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await call();
      reloads += 1;
    } catch (e) {
      error = handle(e);
    } finally {
      busy = false;
    }
  }

  function shutdown(room: api.RoomRow) {
    const reason = window.prompt(
      `Shut down ${room.name ?? room.room_id}?\n\n` +
        'Every local member is made to leave and the room is closed to joins. ' +
        'The events stay on disk — this is not a purge.\n\nReason (optional):',
      '',
    );
    if (reason === null) return;
    run(async () => {
      report = await api.shutdownRoom(room.room_id, true, reason || null);
    });
  }

  $effect(() => {
    void reloads;
    void load(cursors[page] ?? null);
  });
</script>

<h1>Rooms</h1>
<p class="sub">Rooms this server hosts, plus every room it has closed to joins.</p>

{#if error}<div class="notice error">{error}</div>{/if}
{#if report}
  <div class="notice ok">
    Shut down {report.room_id}: {report.kicked.length} member(s) removed{report.blocked
      ? ', room blocked'
      : ''}{report.failed.length > 0 ? `, ${report.failed.length} failed` : ''}.
  </div>
{/if}

<table>
  <thead>
    <tr>
      <th>Room</th>
      <th>Join rule</th>
      <th class="right">Members</th>
      <th class="right">Local</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {#each rooms as room (room.room_id)}
      <tr>
        <td>
          <div>{room.name ?? room.canonical_alias ?? '(unnamed)'}</div>
          <div class="mono muted small">{room.room_id}</div>
        </td>
        <td>
          <span class="badge">{room.join_rule}</span>
          {#if room.is_space}<span class="badge">space</span>{/if}
          {#if room.blocked}<span class="badge danger">blocked</span>{/if}
        </td>
        <td class="right">{room.joined_members}</td>
        <td class="right">{room.local_joined_members}</td>
        <td class="right">
          {#if room.blocked}
            <button
              class="link"
              disabled={busy}
              onclick={() => run(() => api.setRoomBlocked(room.room_id, false))}>Unblock</button
            >
          {:else}
            <button class="link" disabled={busy} onclick={() => shutdown(room)}>Shut down</button>
          {/if}
        </td>
      </tr>
    {:else}
      <tr><td colspan="5" class="empty">{loading ? 'Loading…' : 'No rooms.'}</td></tr>
    {/each}
  </tbody>
</table>

<div class="row" style="margin-top:1rem; justify-content:flex-end">
  <span class="muted small">Page {page + 1}</span>
  <button onclick={() => page > 0 && (page -= 1)} disabled={page === 0 || loading}>Previous</button>
  <button
    onclick={() => {
      if (nextFrom === null) return;
      if (page + 1 >= cursors.length) cursors.push(nextFrom);
      page += 1;
    }}
    disabled={nextFrom === null || loading}>Next</button
  >
</div>

<h2>Blocked rooms</h2>
<p class="muted small">
  A block can name a room this server does not host — the only way to stop local
  users joining somewhere else. Those rooms appear here and nowhere else.
  Blocking a remote room prevents joins; it does not remove members already in it.
</p>
<div class="panel stack">
  <table>
    <thead>
      <tr><th>Room</th><th>Blocked by</th><th>When</th><th></th></tr>
    </thead>
    <tbody>
      {#each blocked as room (room.room_id)}
        <tr>
          <td class="mono">
            {room.room_id}
            {#if !room.hosted}<span class="badge">not hosted</span>{/if}
          </td>
          <td class="mono small">{room.by}</td>
          <td class="muted small">{ts(room.ts)}</td>
          <td class="right">
            <button
              class="link"
              disabled={busy}
              onclick={() => run(() => api.setRoomBlocked(room.room_id, false))}>Unblock</button
            >
          </td>
        </tr>
      {:else}
        <tr><td colspan="4" class="empty">No blocked rooms.</td></tr>
      {/each}
    </tbody>
  </table>
  <div class="row">
    <label class="field" style="flex:1">
      Block a room by id
      <input bind:value={blockRoomId} placeholder="!abuse:remote.example" class="mono" />
    </label>
    <button
      disabled={busy || blockRoomId.length === 0}
      onclick={() =>
        run(async () => {
          await api.setRoomBlocked(blockRoomId, true);
          blockRoomId = '';
        })}>Block</button
    >
  </div>
</div>
