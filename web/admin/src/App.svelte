<script lang="ts">
  import { session, signOut, restore } from './lib/session.svelte';
  import { route, href, link } from './lib/router.svelte';
  import Login from './routes/Login.svelte';
  import Users from './routes/Users.svelte';
  import UserDetail from './routes/UserDetail.svelte';
  import Tokens from './routes/Tokens.svelte';
  import Rooms from './routes/Rooms.svelte';
  import Cluster from './routes/Cluster.svelte';

  const NAV = [
    { path: '/users', label: 'Users' },
    { path: '/tokens', label: 'Registration tokens' },
    { path: '/rooms', label: 'Rooms' },
    { path: '/cluster', label: 'Cluster' },
  ];

  // The one place routes are matched. Everything is a prefix test except
  // the user detail page, which carries an id.
  const userId = $derived(
    route.path.startsWith('/users/')
      ? decodeURIComponent(route.path.slice('/users/'.length))
      : null,
  );
  const section = $derived(
    route.path === '/' ? '/users' : `/${route.path.split('/')[1] ?? 'users'}`,
  );

  // A reload keeps the token but not the identity behind it.
  $effect(() => {
    void restore();
  });
</script>

{#if session.token === null}
  <Login />
{:else if session.forbidden}
  <div class="centre">
    <div class="panel stack">
      <h1>Not an administrator</h1>
      <p class="muted">
        This account signed in, but the server does not consider it a server
        administrator. Ask an existing administrator to grant it, or add the
        account to <code>client.admin_users</code> in the server config.
      </p>
      <button onclick={signOut}>Sign out</button>
    </div>
  </div>
{:else}
  <header class="top">
    <span class="brand">saltator admin</span>
    <nav>
      {#each NAV as item (item.path)}
        <a
          href={href(item.path)}
          onclick={link}
          class:active={section === item.path}>{item.label}</a
        >
      {/each}
    </nav>
    <span class="who">
      {#if session.userId}<span class="mono">{session.userId}</span>{/if}
      <button class="link" onclick={signOut}>Sign out</button>
    </span>
  </header>
  <main>
    {#if userId !== null}
      <UserDetail {userId} />
    {:else if section === '/tokens'}
      <Tokens />
    {:else if section === '/rooms'}
      <Rooms />
    {:else if section === '/cluster'}
      <Cluster />
    {:else}
      <Users />
    {/if}
  </main>
{/if}
