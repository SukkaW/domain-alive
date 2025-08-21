/**
 * This provides an extra layer of protection against concurrent access.
 * This prevents storming the cache implementation and DNS/WHOIS/RDAP.
 */
export function createAsyncMutex<T>() {
  const lock = new Map<string, Promise<T>>();

  return function withLock(key: string, fn: () => Promise<T>): Promise<T> {
    if (lock.has(key)) {
      return lock.get(key)!;
    }

    const p = fn().finally(() => lock.delete(key));
    lock.set(key, p);

    return p;
  };
}
