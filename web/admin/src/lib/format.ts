/// Timestamps come off the API as milliseconds since the epoch. Rendered
/// in the operator's own locale and zone: this is a tool for one person
/// looking at their own server, not a shared report.
export function ts(millis: number | null): string {
  if (millis === null || millis === 0) return '—';
  return new Date(millis).toLocaleString();
}

/// A count with its unit, singular where it matters.
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
