/**
 * Runs scrypt off the main thread.
 *
 * crypto.js's scrypt() is a from-spec implementation whose ROMix step
 * is a tight synchronous loop with no `await` in it. On the main
 * thread that freezes the tab outright for the whole derivation — no
 * repaint, no input, the spinner you just showed sitting perfectly
 * still. Moving the identical computation here makes it no faster,
 * but the page stays alive while it runs.
 */
importScripts("crypto.js?v=2");

self.onmessage = async (e) => {
  const { id, op, password, salt, n } = e.data;
  try {
    const result =
      op === "deriveKeyFromPassword"
        ? { key: await KoshaCrypto.deriveKeyFromPassword(password, salt, 32, n) }
        : await KoshaCrypto.deriveSplitKeys(password, salt, n);
    self.postMessage({ id, ...result });
  } catch (err) {
    self.postMessage({ id, error: err.message || String(err) });
  }
};
