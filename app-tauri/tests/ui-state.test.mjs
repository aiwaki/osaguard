import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeUpdateStatus,
  passwordOutcome,
  updateActionInProgress,
  updateIsInstallable,
} from "../src/ui-state.mjs";

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
