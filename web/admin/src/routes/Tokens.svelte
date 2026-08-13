<script lang="ts">
  import * as api from '../lib/api';
  import { handle } from '../lib/session.svelte';
  import { ts } from '../lib/format';

  let tokens = $state<api.RegToken[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let reloads = $state(0);

  let uses = $state('');
  let expiryDays = $state('');

  async function load() {
    loading = true;
    error = null;
    try {
      tokens = (await api.listTokens()).registration_tokens;
    } catch (e) {
      error = handle(e);
    } finally {
      loading = false;
    }
  }

  async function create() {
    busy = true;
    error = null;
    try {
      // The server mints the token itself: an operator picking one by hand
      // tends to pick a guessable one.
      await api.createToken({
        uses_allowed: uses === '' ? undefined : Number(uses),
        expiry_ts:
          expiryDays === ''
            ? undefined
            : Date.now() + Number(expiryDays) * 24 * 60 * 60 * 1000,
      });
      uses = '';
      expiryDays = '';
      reloads += 1;
    } catch (e) {
      error = handle(e);
    } finally {
      busy = false;
    }
  }

  async function remove(token: string) {
    if (!window.confirm(`Delete token ${token}?`)) return;
    busy = true;
    try {
      await api.deleteToken(token);
      reloads += 1;
    } catch (e) {
      error = handle(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    void reloads;
    void load();
  });
</script>

<h1>Registration tokens</h1>
<p class="sub">
  Invite codes for a closed server. They apply only when
  <code>client.registration_requires_token</code> is on — and turning that on before
  an administrator exists locks the server with nobody inside.
</p>

{#if error}<div class="notice error">{error}</div>{/if}

<div class="panel row" style="margin-bottom:1.25rem">
  <label class="field">
    Uses allowed
    <input bind:value={uses} type="number" min="1" placeholder="unlimited" />
  </label>
  <label class="field">
    Expires in (days)
    <input bind:value={expiryDays} type="number" min="1" placeholder="never" />
  </label>
  <button class="primary" onclick={create} disabled={busy}>Mint token</button>
</div>

<table>
  <thead>
    <tr>
      <th>Token</th>
      <th>Uses</th>
      <th>Expires</th>
      <th>Created</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {#each tokens as token (token.token)}
      <tr>
        <td class="mono">
          {token.token}
          {#if !token.valid}<span class="badge warn">spent</span>{/if}
        </td>
        <td>{token.used} / {token.uses_allowed ?? '∞'}</td>
        <td class="muted small">{token.expiry_ts === null ? 'never' : ts(token.expiry_ts)}</td>
        <td class="muted small">{ts(token.created_ts)}</td>
        <td class="right">
          <button class="link" disabled={busy} onclick={() => remove(token.token)}>Delete</button>
        </td>
      </tr>
    {:else}
      <tr><td colspan="5" class="empty">{loading ? 'Loading…' : 'No tokens.'}</td></tr>
    {/each}
  </tbody>
</table>
