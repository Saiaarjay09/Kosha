/**
 * Main-thread handle for scrypt-worker.js — the same call shape as
 * KoshaCrypto.deriveSplitKeys, just routed through a Worker. One
 * worker is reused for the page's lifetime rather than spun up per
 * call, and requests carry an incrementing id because signup asks for
 * two derivations (password and recovery phrase) without waiting for
 * the first to land.
 */
const KoshaScrypt = (() => {
  "use strict";

  let worker = null;
  let nextId = 1;
  const pending = new Map();

  function getWorker() {
    if (worker) return worker;
    worker = new Worker("js/scrypt-worker.js?v=2");
    worker.onmessage = (e) => {
      const { id, error, ...result } = e.data;
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      if (error) p.reject(new Error(error));
      else p.resolve(result);
    };
    worker.onerror = (e) => {
      // A worker-level crash has no per-request id to route to, so
      // fail everything still waiting rather than hang it forever.
      for (const p of pending.values()) p.reject(new Error(e.message || "key derivation failed"));
      pending.clear();
    };
    return worker;
  }

  function call(op, password, saltBytes, n) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      getWorker().postMessage({ id, op, password, salt: saltBytes, n });
    });
  }

  return {
    deriveSplitKeys: (password, salt, n) => call("deriveSplitKeys", password, salt, n),
    deriveKeyFromPassword: (password, salt, n) => call("deriveKeyFromPassword", password, salt, n).then((r) => r.key),
  };
})();
