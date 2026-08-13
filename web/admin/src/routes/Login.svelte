<script lang="ts">
  import { signIn } from '../lib/session.svelte';
  import { ApiError } from '../lib/api';

  let user = $state('');
  let password = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = null;
    try {
      await signIn(user, password);
    } catch (e) {
      // A wrong password and a non-existent account are the same 403 by
      // design; say so the same way rather than inventing a distinction
      // the server deliberately does not make.
      error =
        e instanceof ApiError && e.status === 403
          ? 'Incorrect username or password.'
          : e instanceof Error
            ? e.message
            : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="centre">
  <form class="panel stack" onsubmit={submit}>
    <h1>saltator admin</h1>
    <p class="sub" style="margin:0">Sign in with a server administrator account.</p>
    {#if error}<div class="notice error">{error}</div>{/if}
    <label class="field">
      Username
      <!-- svelte-ignore a11y_autofocus -->
      <input bind:value={user} autocomplete="username" autofocus required />
    </label>
    <label class="field">
      Password
      <input type="password" bind:value={password} autocomplete="current-password" required />
    </label>
    <button class="primary" type="submit" disabled={busy}>
      {busy ? 'Signing in…' : 'Sign in'}
    </button>
  </form>
</div>
