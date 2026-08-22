import assert from "node:assert/strict";
import test from "node:test";

import {
  bootstrapRuntime,
  normalizeUpdateStatus,
  passwordOutcome,
  updateActionInProgress,
  updateIsInstallable,
} from "../src/ui-state.mjs";

test("bootstrap loads status before subscribing and reports success", async () => {
  const calls = [];
  const ready = [];
  const errors = [];
  const result = await bootstrapRuntime({
    loadStatus: async () => calls.push("status"),
    subscribe: async (event) => calls.push(event),
    subscriptions: [
      { event: "first", handler: () => {} },
      { event: "second", handler: () => {} },
    ],
    onReady: () => ready.push(true),
    onError: (error) => errors.push(error),
  });

  assert.equal(result, true);
  assert.equal(calls[0], "status");
  assert.deepEqual(new Set(calls.slice(1)), new Set(["first", "second"]));
  assert.deepEqual(ready, [true]);
  assert.deepEqual(errors, []);
});

test("bootstrap turns startup failures into a visible error state", async () => {
  const failure = new Error("event permission denied");
  const errors = [];
  let ready = false;
  const result = await bootstrapRuntime({
    loadStatus: async () => {},
    subscribe: async () => {
      throw failure;
    },
    subscriptions: [{ event: "blocked", handler: () => {} }],
    onReady: () => {
      ready = true;
    },
    onError: (error) => errors.push(error),
  });

  assert.equal(result, false);
  assert.equal(ready, false);
  assert.deepEqual(errors, [failure]);
});

test("an unconfigured build always exposes the unconfigured phase", () => {
  assert.deepEqual(
    normalizeUpdateStatus({
      configured: false,
      phase: "available",
      version: " 0.2.0 ",
      errorCode: null,
    }),
    {
      configured: false,
      phase: "unconfigured",
      version: "0.2.0",
      errorCode: null,
    },
  );
});

test("unknown update phases fall back without becoming installable", () => {
  const update = normalizeUpdateStatus({ configured: true, phase: "mystery" });
  assert.equal(update.phase, "idle");
  assert.equal(updateIsInstallable(update), false);
});

test("available and ready updates with versions are installable", () => {
  for (const phase of ["available", "ready"]) {
    assert.equal(
      updateIsInstallable({ configured: true, phase, version: "0.2.0" }),
      true,
    );
  }
  assert.equal(
    updateIsInstallable({ configured: true, phase: "available", version: null }),
    false,
  );
});

test("only active update work is treated as in progress", () => {
  for (const phase of ["checking", "downloading", "installing"]) {
    assert.equal(updateActionInProgress({ configured: true, phase }), true);
  }
  for (const phase of ["idle", "up_to_date", "available", "ready", "error"]) {
    assert.equal(updateActionInProgress({ configured: true, phase }), false);
  }
});

test("password actions accept only structured outcomes", () => {
  assert.equal(passwordOutcome({ outcome: "saved" }), "saved");
  assert.equal(passwordOutcome({ outcome: "cancelled" }), "cancelled");
  assert.equal(passwordOutcome({ outcome: "already_open" }), "already_open");
  assert.equal(passwordOutcome({ outcome: "failed" }), null);
  assert.equal(passwordOutcome(null), null);
});
