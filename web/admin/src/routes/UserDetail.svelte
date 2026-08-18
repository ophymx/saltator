<script lang="ts">
  import * as api from '../lib/api';
  import { handle, session } from '../lib/session.svelte';
  import { href, link } from '../lib/router.svelte';
  import { ts, plural } from '../lib/format';

  let { userId }: { userId: string } = $props();

  let user = $state<api.UserDetail | null>(null);
  let error = $state<string | null>(null);
  let done = $state<string | null>(null);
  let busy = $state(false);

  // Form state for the actions that need input.
  let newPassword = $state('');
  let logoutDevices = $state(true);
  let erase = $state(false);
  let provider = $state('');
  let externalId = $state('');
  let noticeBody = $state('');

  const isSelf = $derived(session.userId === userId);

  async function load() {
    try {
      user = await api.getUser(userId);
    } catch (e) {
      error = handle(e);
    }
  }

  /// Run one admin action, keeping the page in step with the result.
  /// Every mutation endpoint answers with the account's new state, so
  /// nothing here has to re-read to find out what it just did.
  async function act(
    label: string,
    call: () => Promise<api.UserDetail | unknown>,
    reload = false,
  ) {
    busy = true;
    error = null;
    done = null;
    try {
      const result = await call();
      if (reload) await load();
      else user = result as api.UserDetail;
      done = label;
    } catch (e) {
      error = handle(e);
    } finally {
      busy = false;
    }
  }

  function confirmed(question: string): boolean {
    return window.confirm(question);
  }

  $effect(() => {
    void load();
  });
</script>

<p class="small"><a href={href('/users')} onclick={link}>← All users</a></p>

{#if error}<div class="notice error">{error}</div>{/if}
{#if done}<div class="notice ok">{done}</div>{/if}

{#if user === null}
  <p class="empty">Loading…</p>
{:else}
  {@const u = user}
  <div class="spread">
    <div>
      <h1 class="mono">{u.user_id}</h1>
      <p class="sub">
        {u.displayname ?? 'no display name'} · created {ts(u.created_ts)}
      </p>
    </div>
    <div class="row">
      <span
        class="badge"
        class:ok={u.state === 'active'}
        class:warn={u.state === 'locked'}
        class:danger={u.state === 'deactivated'}>{u.state}</span
      >
      {#if u.admin}<span class="badge">admin</span>{/if}
      {#if u.erased}<span class="badge danger">erased</span>{/if}
      {#if !u.has_password}<span class="badge">no password</span>{/if}
    </div>
  </div>

  {#if isSelf}
    <div class="notice">
      This is the account you are signed in as. The server refuses actions that
      would remove your own access.
    </div>
  {/if}

  <h2>Account</h2>
  <div class="panel stack">
    <div class="row">
      {#if u.state === 'locked'}
        <button
          disabled={busy}
          onclick={() => act('Account unlocked.', () => api.setLocked(u.user_id, false))}
          >Unlock</button
        >
      {:else}
        <button
          disabled={busy || u.state === 'deactivated' || isSelf}
          onclick={() => act('Account locked.', () => api.setLocked(u.user_id, true))}
          >Lock</button
        >
      {/if}
      <span class="muted small">
        Locking is reversible and destroys nothing: tokens stop working, the
        user's rooms and data are untouched.
      </span>
    </div>

    <div class="row">
      <button
        disabled={busy || u.admin}
        onclick={() => act('Administrator rights granted.', () => api.setAdmin(u.user_id, true))}
        >Grant admin</button
      >
      <button
        disabled={busy || !u.admin || isSelf}
        onclick={() => act('Administrator rights revoked.', () => api.setAdmin(u.user_id, false))}
        >Revoke admin</button
      >
    </div>

    <div class="row">
      <label class="check">
        <input type="checkbox" bind:checked={erase} />
        also erase
      </label>
      <button
        class="danger"
        disabled={busy || u.state === 'deactivated' || isSelf}
        onclick={() =>
          confirmed(`Permanently deactivate ${u.user_id}? This cannot be undone.`) &&
          act('Account deactivated.', () => api.deactivate(u.user_id, erase))}
        >Deactivate</button
      >
      <span class="muted small">
        Permanent. Erasure additionally clears the profile — it does
        <strong>not</strong> redact the user's messages, which is not implemented.
      </span>
    </div>
  </div>

  <h2>Password</h2>
  <div class="panel">
    <div class="row">
      <label class="field" style="flex:1">
        New password
        <input type="password" bind:value={newPassword} autocomplete="new-password" />
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={logoutDevices} />
        sign out every session
      </label>
      <button
        disabled={busy || newPassword.length === 0}
        onclick={() =>
          act('Password reset.', () =>
            api.resetPassword(u.user_id, newPassword, logoutDevices),
          ).then(() => (newPassword = ''))}>Reset</button
      >
    </div>
  </div>

  <h2>Sessions <span class="muted small">({plural(u.devices.length, 'device')})</span></h2>
  <div class="panel">
    <table>
      <thead>
        <tr><th>Device</th><th>Name</th><th class="right">Created</th><th></th></tr>
      </thead>
      <tbody>
        {#each u.devices as device (device.device_id)}
          <tr>
            <td class="mono">{device.device_id}</td>
            <td>{device.display_name ?? '—'}</td>
            <td class="right muted small">{ts(device.created_ts)}</td>
            <td class="right">
              <button
                class="link"
                disabled={busy}
                onclick={() =>
                  act('Session revoked.', () => api.deleteDevice(u.user_id, device.device_id))}
                >Revoke</button
              >
            </td>
          </tr>
        {:else}
          <tr><td colspan="4" class="empty">No sessions.</td></tr>
        {/each}
      </tbody>
    </table>
    {#if u.devices.length > 0}
      <div class="row" style="margin-top:0.75rem; justify-content:flex-end">
        <button
          class="danger"
          disabled={busy}
          onclick={() =>
            confirmed(`Sign ${u.user_id} out of every session?`) &&
            act('All sessions revoked.', () => api.deleteDevice(u.user_id))}
          >Revoke all</button
        >
      </div>
    {/if}
  </div>

  <h2>Identity links</h2>
  <div class="panel stack">
    <p class="muted small" style="margin:0">
      Links to external identity providers. Writable before any provider is
      configured — pre-linking accounts and then enabling the IdP is what
      avoids a flag day.
    </p>
    <table>
      <thead>
        <tr><th>Provider</th><th>Subject</th><th></th></tr>
      </thead>
      <tbody>
        {#each u.external_ids as ext (ext.auth_provider)}
          <tr>
            <td class="mono">{ext.auth_provider}</td>
            <td class="mono">{ext.external_id}</td>
            <td class="right">
              <button
                class="link"
                disabled={busy}
                onclick={() =>
                  act('Link removed.', () =>
                    api.unlinkExternalId(u.user_id, ext.auth_provider),
                  )}>Unlink</button
              >
            </td>
          </tr>
        {:else}
          <tr><td colspan="3" class="empty">No links.</td></tr>
        {/each}
      </tbody>
    </table>
    <div class="row">
      <label class="field"
        >Provider<input bind:value={provider} placeholder="oidc-keycloak" /></label
      >
      <label class="field" style="flex:1"
        >Subject<input bind:value={externalId} placeholder="external id at the provider" /></label
      >
      <button
        disabled={busy || provider.length === 0 || externalId.length === 0}
        onclick={() =>
          act('Link written.', () =>
            api.linkExternalId(u.user_id, provider, externalId),
          ).then(() => {
            provider = '';
            externalId = '';
          })}>Link</button
      >
    </div>
  </div>

  <h2>Server notice</h2>
  <div class="panel row">
    <label class="field" style="flex:1">
      Message
      <input bind:value={noticeBody} placeholder="Scheduled maintenance at 02:00 UTC" />
    </label>
    <button
      disabled={busy || noticeBody.length === 0}
      onclick={() =>
        act('Notice sent.', () => api.sendNotice(u.user_id, noticeBody), true).then(
          () => (noticeBody = ''),
        )}>Send</button
    >
  </div>
{/if}
