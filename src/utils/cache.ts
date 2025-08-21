type MaybePromise<T> = T | Promise<T>;

export type CacheImplementation<T> = SyncCacheImplementation<T> | AsyncCacheImplementation<T>;

export interface SyncCacheImplementation<T> {
  get(key: string): T | undefined | null,
  set(key: string, value: T): void,
  has(key: string): boolean
}

export interface AsyncCacheImplementation<T> {
  get(key: string): Promise<T | undefined | null>,
  set(key: string, value: T): Promise<void>,
  has(key: string): Promise<boolean>
}

export async function cacheApply<T>(cache: CacheImplementation<T> | undefined, key: string, fn: () => MaybePromise<T>): Promise<T> {
  if (cache?.has(key)) {
    return cache.get(key) as MaybePromise<T>;
  }

  const result = await fn();
  if (cache) {
    await cache.set(key, result);
  }

  return result;
};
