const UPDATE_PHASES = new Set([
  "unconfigured",
  "idle",
  "checking",
  "up_to_date",
  "available",
  "downloading",
  "ready",
  "installing",
  "error",
]);

export function normalizeUpdateStatus(value) {
  const configured = value?.configured === true;
  const requestedPhase = typeof value?.phase === "string" ? value.phase : "";
  const phase = UPDATE_PHASES.has(requestedPhase)
    ? requestedPhase
    : configured
      ? "idle"
      : "unconfigured";

  return {
    configured,
    phase: configured ? phase : "unconfigured",
    version:
      typeof value?.version === "string" && value.version.trim()
        ? value.version.trim()
        : null,
    errorCode:
      typeof value?.errorCode === "string" && value.errorCode.trim()
        ? value.errorCode.trim()
        : null,
  };
}

export function passwordOutcome(value) {
  const outcome = value?.outcome;
  return outcome === "saved" || outcome === "cancelled" || outcome === "already_open"
    ? outcome
    : null;
}

export function updateIsInstallable(value) {
  const update = normalizeUpdateStatus(value);
  return (
    update.configured &&
    (update.phase === "available" || update.phase === "ready") &&
    Boolean(update.version)
  );
}

export function updateActionInProgress(value) {
  const phase = normalizeUpdateStatus(value).phase;
  return phase === "checking" || phase === "downloading" || phase === "installing";
}
