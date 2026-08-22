import {
  bootstrapRuntime,
  normalizeUpdateStatus,
  passwordOutcome,
  updateActionInProgress,
  updateIsInstallable,
} from "./ui-state.mjs";

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const copy = {
  en: {
    systemLanguage: "System language · English",
    installEyebrow: "First launch",
    installTitle: "Install OsaGuard in Applications",
    installCopy:
      "The menu-bar app, native password broker and updater must stay inside one signed app. Install it once, then complete the three setup steps.",
    installStep1: "Copy",
    installStep1Copy: "OsaGuard.app goes to Applications.",
    installStep2: "Relaunch",
    installStep2Copy: "The installed copy opens automatically.",
    installStep3: "Set up",
    installStep3Copy: "Grant access and enter your password once.",
    installButton: "Install in Applications",
    installFootnote:
      "OsaGuard never configures Accessibility, saves a password or starts at login while running from Downloads or a mounted DMG.",
    setupEyebrow: "One-time setup",
    setupTitle: "Three clear steps. No Terminal.",
    setupCopy:
      "The password stays in macOS Keychain. OsaGuard’s web interface never receives it — a native secure dialog handles entry.",
    progress: (done) => `${done} of 3 complete`,
    done: "Done",
    waiting: "Required",
    finalStep: "Final step",
    accessibilityTitle: "Allow Accessibility",
    accessibilityCopy:
      "macOS uses this permission so OsaGuard can detect the genuine secure field and type into that exact process. You must turn OsaGuard on once in System Settings.",
    accessibilityButton: "Request access",
    accessibilitySettingsButton: "Open Accessibility settings",
    accessibilityRecoveryCopy:
      "Finish in macOS’s own prompt. If OsaGuard is already on but this step stays incomplete after a few seconds, remove the old OsaGuard entry with the − button. Replaced local builds can have a new identity. Then return here and request access again.",
    passwordTitle: "Save administrator password",
    passwordCopy:
      "Opens a native protected field. The password is stored only in Keychain on this Mac; it is never shown, copied, logged or sent.",
    passwordButton: "Enter password once",
    automaticTitle: "Confirm automatic mode",
    automaticCopy:
      "Review the serious security trade-off before enabling automatic confirmation. Once enabled, it works without later clicks.",
    automaticButton: "Review security warning",
    riskTitle: "This is passwordless administrator access",
    riskBody:
      "While OsaGuard is enabled, any process running in your macOS account can open a genuine AppleScript administrator request and gain root access without knowing your password.\n\nApple’s signature proves that the dialog is genuine — it does not prove that the requested command is safe. macOS also does not expose which client opened a SecurityAgent dialog, so a different genuine administrator dialog appearing in the same short time window can receive the saved password. Continue only if you accept these risks.",
    riskConfirm: "Enable automatic mode",
    notNow: "Not now",
    cancel: "Cancel",
    dashboardEyebrow: "OsaGuard status",
    activeTitle: "Automatic confirmation is on",
    pausedTitle: "Automatic confirmation is paused",
    activeCopy:
      "OsaGuard is watching for genuine AppleScript administrator dialogs and will submit the saved password automatically.",
    pausedCopy:
      "Your password remains in Keychain, but OsaGuard will not type or submit it until you resume.",
    pause: "Pause",
    resume: "Resume",
    accessibilityPanel: "Accessibility",
    granted: "Allowed",
    missing: "Missing",
    accessibilityPanelCopy: "Required for focused, process-targeted input.",
    fix: "Fix access",
    passwordPanel: "Saved password",
    saved: "Stored in Keychain",
    notSaved: "Not stored",
    passwordPanelCopy: "The app can replace or delete it, but never display it.",
    change: "Change…",
    remove: "Remove…",
    updatePanel: "Updates",
    updateAutomatic: "Checked at startup and every 6 hours",
    updateChecking: "Checking…",
    updateAvailable: (version) => `Version ${version} is available`,
    updateDownloading: (version) =>
      version ? `Downloading OsaGuard ${version}…` : "Downloading update…",
    updateReady: (version) =>
      version ? `OsaGuard ${version} is ready to install` : "Update is ready to install",
    updateInstalling: "Installing and restarting…",
    updateCurrent: "Up to date",
    updateUnavailable: "Updates unavailable in this preview build",
    updateBusy: "Another update action is already running",
    updateVersionChanged:
      "A newer update became available. Review the new version before installing it",
    updateManualRequired:
      "This installation can’t be replaced automatically. Install the newest DMG manually",
    updateNotInstalled:
      "Install OsaGuard in Applications before using automatic updates",
    updateAuthDialogActive:
      "Close the current administrator prompt, then install the update",
    updateAuthDialogCheckFailed:
      "Couldn’t confirm that the administrator prompt is closed",
    updateCheckFailed: "Couldn’t check for updates",
    updateDownloadFailed: "Couldn’t download the update",
    updateInstallFailed: "Couldn’t install the update",
    updateWatcherStopFailed: "Couldn’t pause automatic confirmation for the update",
    updateWatcherRestoreFailed:
      "The update failed and automatic confirmation could not be resumed",
    updateError: "Last check failed",
    updatePanelCopy: "Signed releases are verified before installation.",
    checkNow: "Check now",
    installUpdate: (version) => `Install OsaGuard ${version}`,
    permanentRisk:
      "While automatic confirmation is enabled, any process running in your account can use a genuine AppleScript administrator request to gain root access without your password. A different genuine administrator dialog appearing at the same time can also receive the saved password because macOS does not expose the requesting client.",
    securityNote: "Security trade-off",
    removeTitle: "Remove the saved password?",
    removeBody:
      "Automatic confirmation will stop immediately. OsaGuard will delete every Keychain password item it can verify belongs to this installed app; this cannot be undone without entering the password again.",
    removeConfirm: "Remove password",
    updateTitle: "Install the update now?",
    updateBody:
      "OsaGuard will download and verify the signed update first. It will then make sure no administrator prompt is open, briefly pause automatic confirmation, install the update, and restart.",
    updateConfirm: "Install and restart",
    uninstallTitle: "Uninstall OsaGuard?",
    uninstallBody:
      "Automatic confirmation and launch at login will stop. OsaGuard will remove its verified Keychain password items and settings, reset its Accessibility entry, and move the app to Trash. The app can be recovered until Trash is emptied.",
    uninstallConfirm: "Uninstall and move to Trash",
    uninstallError: "Couldn’t uninstall OsaGuard.",
    accessFollowup:
      "OsaGuard requested access. Use the macOS prompt; if you choose Deny, you can open Accessibility settings from OsaGuard afterward.",
    accessSettingsOpened:
      "After changing Accessibility, return to OsaGuard. This page checks the permission automatically.",
    passwordSavedToast: "Password saved in macOS Keychain.",
    passwordSaveError: "Couldn’t save the password. The previous password was not changed.",
    automaticActionError: "Couldn’t change automatic confirmation.",
    runtimeActionError: "OsaGuard couldn’t complete the requested action.",
    enabledToast: "Automatic confirmation enabled.",
    pausedToast: "Automatic confirmation paused.",
    resumedToast: "Automatic confirmation resumed.",
    passwordRemovedToast: "Saved password removed and automatic confirmation stopped.",
    upToDateToast: "OsaGuard is up to date.",
    updateAvailableToast: (version) => `OsaGuard ${version} is ready to install.`,
    genericError: "OsaGuard could not complete that action.",
    startupErrorTitle: "OsaGuard couldn’t start",
    startupErrorCopy:
      "The dashboard could not connect to the protected native service. Quit OsaGuard, open it again, and install the newest release if this continues.",
    retry: "Try again",
  },
  ru: {
    systemLanguage: "Язык системы · Русский",
    installEyebrow: "Первый запуск",
    installTitle: "Установите OsaGuard в «Программы»",
    installCopy:
      "Приложение в строке меню, нативное хранилище пароля и обновлятор должны оставаться внутри одного подписанного приложения. Установите его один раз, затем пройдите три шага настройки.",
    installStep1: "Копирование",
    installStep1Copy: "OsaGuard.app попадёт в «Программы».",
    installStep2: "Перезапуск",
    installStep2Copy: "Установленная копия откроется сама.",
    installStep3: "Настройка",
    installStep3Copy: "Разрешите доступ и один раз введите пароль.",
    installButton: "Установить в «Программы»",
    installFootnote:
      "При запуске из «Загрузок» или подключённого DMG OsaGuard не настраивает Accessibility, не сохраняет пароль и не добавляется в автозапуск.",
    setupEyebrow: "Одноразовая настройка",
    setupTitle: "Три понятных шага. Без Терминала.",
    setupCopy:
      "Пароль остаётся в Связке ключей macOS. Веб-интерфейс OsaGuard его не получает — ввод обрабатывает нативное защищённое окно.",
    progress: (done) => `Готово ${done} из 3`,
    done: "Готово",
    waiting: "Нужно сделать",
    finalStep: "Финальный шаг",
    accessibilityTitle: "Разрешите Accessibility",
    accessibilityCopy:
      "Это разрешение нужно macOS, чтобы OsaGuard увидел настоящее защищённое поле и ввёл текст именно в этот процесс. Один раз включите OsaGuard в Системных настройках.",
    accessibilityButton: "Запросить доступ",
    accessibilitySettingsButton: "Открыть «Универсальный доступ»",
    accessibilityRecoveryCopy:
      "Завершите действие в системном окне macOS. Если OsaGuard уже включён, но шаг не завершается через несколько секунд, удалите старую строку OsaGuard кнопкой «−». После замены локальной сборки её идентичность может измениться. Затем вернитесь сюда и запросите доступ снова.",
    passwordTitle: "Сохраните пароль администратора",
    passwordCopy:
      "Откроется нативное защищённое поле. Пароль хранится только в Связке ключей на этом Mac; он не показывается, не копируется, не попадает в логи и никуда не отправляется.",
    passwordButton: "Один раз ввести пароль",
    automaticTitle: "Подтвердите автоматический режим",
    automaticCopy:
      "Перед включением автоподтверждения прочитайте важное предупреждение о безопасности. После включения дополнительные нажатия не понадобятся.",
    automaticButton: "Прочитать предупреждение",
    riskTitle: "Это беспарольный доступ администратора",
    riskBody:
      "Пока OsaGuard включён, любой процесс в вашей учётной записи macOS может открыть настоящее администраторское окно AppleScript и получить root-доступ, не зная вашего пароля.\n\nПодпись Apple доказывает, что окно настоящее, но не доказывает безопасность запрошенной команды. macOS также не сообщает, какой клиент открыл окно SecurityAgent, поэтому сохранённый пароль может попасть в другое настоящее окно администратора, появившееся в тот же короткий промежуток времени. Продолжайте, только если принимаете эти риски.",
    riskConfirm: "Включить автоматический режим",
    notNow: "Не сейчас",
    cancel: "Отмена",
    dashboardEyebrow: "Состояние OsaGuard",
    activeTitle: "Автоподтверждение включено",
    pausedTitle: "Автоподтверждение приостановлено",
    activeCopy:
      "OsaGuard следит за настоящими администраторскими окнами AppleScript и автоматически отправляет сохранённый пароль.",
    pausedCopy:
      "Пароль остаётся в Связке ключей, но OsaGuard не будет вводить и отправлять его, пока вы не возобновите работу.",
    pause: "Приостановить",
    resume: "Возобновить",
    accessibilityPanel: "Accessibility",
    granted: "Разрешено",
    missing: "Нет доступа",
    accessibilityPanelCopy: "Нужно для прицельного ввода в активный процесс.",
    fix: "Исправить",
    passwordPanel: "Сохранённый пароль",
    saved: "В Связке ключей",
    notSaved: "Не сохранён",
    passwordPanelCopy: "Приложение может заменить или удалить его, но не показать.",
    change: "Изменить…",
    remove: "Удалить…",
    updatePanel: "Обновления",
    updateAutomatic: "Проверка при запуске и каждые 6 часов",
    updateChecking: "Проверка…",
    updateAvailable: (version) => `Доступна версия ${version}`,
    updateDownloading: (version) =>
      version ? `Загрузка OsaGuard ${version}…` : "Загрузка обновления…",
    updateReady: (version) =>
      version ? `OsaGuard ${version} готов к установке` : "Обновление готово к установке",
    updateInstalling: "Установка и перезапуск…",
    updateCurrent: "Установлена последняя версия",
    updateUnavailable: "Обновления недоступны в этой preview-сборке",
    updateBusy: "Другое действие с обновлением уже выполняется",
    updateVersionChanged:
      "Появилась другая версия. Перед установкой проверьте новое обновление",
    updateManualRequired:
      "Эту установку нельзя заменить автоматически. Установите новый DMG вручную",
    updateNotInstalled:
      "Сначала установите OsaGuard в «Программы», затем используйте автообновление",
    updateAuthDialogActive:
      "Закройте текущее окно администратора, затем установите обновление",
    updateAuthDialogCheckFailed:
      "Не удалось убедиться, что окно администратора закрыто",
    updateCheckFailed: "Не удалось проверить обновления",
    updateDownloadFailed: "Не удалось загрузить обновление",
    updateInstallFailed: "Не удалось установить обновление",
    updateWatcherStopFailed: "Не удалось приостановить автоподтверждение для обновления",
    updateWatcherRestoreFailed:
      "Обновление не установлено, а автоподтверждение не удалось возобновить",
    updateError: "Последняя проверка не удалась",
    updatePanelCopy: "Подписанные релизы проверяются перед установкой.",
    checkNow: "Проверить",
    installUpdate: (version) => `Установить OsaGuard ${version}`,
    permanentRisk:
      "Пока автоподтверждение включено, любой процесс в вашей учётной записи может использовать настоящее администраторское окно AppleScript, чтобы получить root-доступ без вашего пароля. Другое настоящее окно администратора, появившееся одновременно, тоже может получить сохранённый пароль, потому что macOS не сообщает запрашивающий клиент.",
    securityNote: "Цена для безопасности",
    removeTitle: "Удалить сохранённый пароль?",
    removeBody:
      "Автоподтверждение сразу остановится. OsaGuard удалит все объекты пароля из Связки ключей, принадлежность которых этому установленному приложению он может проверить; вернуть их без повторного ввода пароля нельзя.",
    removeConfirm: "Удалить пароль",
    updateTitle: "Установить обновление сейчас?",
    updateBody:
      "Сначала OsaGuard загрузит и проверит подпись обновления. Затем убедится, что окно администратора не открыто, ненадолго приостановит автоподтверждение, установит обновление и перезапустится.",
    updateConfirm: "Установить и перезапустить",
    uninstallTitle: "Удалить OsaGuard?",
    uninstallBody:
      "Автоподтверждение и запуск при входе остановятся. OsaGuard удалит проверенные объекты пароля из Связки ключей и свои настройки, сбросит запись Accessibility и переместит приложение в Корзину. До очистки Корзины приложение можно восстановить.",
    uninstallConfirm: "Удалить в Корзину",
    uninstallError: "Не удалось удалить OsaGuard.",
    accessFollowup:
      "OsaGuard запросил доступ. Используйте системное окно macOS; если нажмёте «Запретить», нужный раздел можно открыть из OsaGuard позже.",
    accessSettingsOpened:
      "После изменения разрешения вернитесь в OsaGuard. Эта страница проверяет доступ автоматически.",
    passwordSavedToast: "Пароль сохранён в Связке ключей macOS.",
    passwordSaveError: "Не удалось сохранить пароль. Прежний пароль не изменён.",
    automaticActionError: "Не удалось изменить состояние автоподтверждения.",
    runtimeActionError: "OsaGuard не смог выполнить запрошенное действие.",
    enabledToast: "Автоподтверждение включено.",
    pausedToast: "Автоподтверждение приостановлено.",
    resumedToast: "Автоподтверждение возобновлено.",
    passwordRemovedToast: "Пароль удалён, автоподтверждение остановлено.",
    upToDateToast: "Установлена последняя версия OsaGuard.",
    updateAvailableToast: (version) => `OsaGuard ${version} готов к установке.`,
    genericError: "OsaGuard не смог выполнить действие.",
    startupErrorTitle: "Не удалось запустить OsaGuard",
    startupErrorCopy:
      "Панель не смогла подключиться к защищённой нативной части приложения. Закройте OsaGuard и откройте снова; если это повторится, установите последнюю версию.",
    retry: "Попробовать снова",
  },
};

const app = document.querySelector("#app");
const toast = document.querySelector("#toast");
const modal = document.querySelector("#modal");
const modalTitle = document.querySelector("#modal-title");
const modalBody = document.querySelector("#modal-body");
const modalCancel = document.querySelector("#modal-cancel");
const modalConfirm = document.querySelector("#modal-confirm");

let status = null;
let language = navigator.language?.toLowerCase().startsWith("ru") ? "ru" : "en";
let t = copy[language];
let modalAction = null;
let toastTimer = null;
let busy = false;
let accessibilityRequestAttempted = false;
let accessibilityRecoveryVisible = false;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function brand(version = "") {
  return `
    <header class="topbar">
      <div class="brand">
        <img src="./icon.png" alt="" />
        <div>
          <div class="brand-name">OsaGuard</div>
          <div class="version">${version ? `v${escapeHtml(version)}` : ""}</div>
        </div>
      </div>
      <div class="system-language">${t.systemLanguage}</div>
    </header>`;
}

function statusBadge(complete) {
  return `<span class="badge ${complete ? "good" : "waiting"}">${complete ? t.done : t.waiting}</span>`;
}

function stepCard({
  number,
  title,
  body,
  complete,
  locked = false,
  dangerous = false,
  action,
  label,
  pendingLabel,
}) {
  return `
    <article class="step-card ${complete ? "complete" : ""} ${locked ? "locked" : ""} ${dangerous ? "danger-step" : ""}">
      <div class="step-number">${complete ? "✓" : number}</div>
      <div>
        <div class="step-title-row">
          <h2 class="step-title">${title}</h2>
          ${complete ? statusBadge(true) : `<span class="badge waiting">${pendingLabel || t.waiting}</span>`}
        </div>
        <p class="step-copy">${body}</p>
      </div>
      ${
        complete
          ? ""
          : `<button class="button ${dangerous ? "danger" : ""}" data-action="${action}" ${locked ? "disabled" : ""}>${label}</button>`
      }
    </article>`;
}

function renderInstall() {
  app.innerHTML = `
    <section class="shell install-screen">
      <article class="install-card">
        <img class="install-logo" src="./icon.png" alt="OsaGuard" />
        <p class="eyebrow">${t.installEyebrow}</p>
        <h1>${t.installTitle}</h1>
        <p class="hero-copy">${t.installCopy}</p>
        <div class="install-flow">
          <div><strong>1 · ${t.installStep1}</strong>${t.installStep1Copy}</div>
          <div><strong>2 · ${t.installStep2}</strong>${t.installStep2Copy}</div>
          <div><strong>3 · ${t.installStep3}</strong>${t.installStep3Copy}</div>
        </div>
        <button class="button large" data-action="install" ${busy ? "disabled" : ""}>${t.installButton}</button>
        <p class="footnote">${t.installFootnote}</p>
      </article>
    </section>`;
}

function renderSetup() {
  const access = status.accessibilityGranted;
  const password = status.passwordSaved;
  const automatic = status.automaticActive;
  const done = [access, password, automatic].filter(Boolean).length;
  app.innerHTML = `
    <section class="shell">
      ${brand(status.version)}
      <div class="hero">
        <p class="eyebrow">${t.setupEyebrow}</p>
        <h1>${t.setupTitle}</h1>
        <p class="hero-copy">${t.setupCopy}</p>
        <div class="progress-row">
          <div class="progress-track"><span class="progress-fill progress-${done}"></span></div>
          <span class="progress-label">${t.progress(done)}</span>
        </div>
      </div>
      <div class="step-list">
        ${stepCard({
          number: 1,
          title: t.accessibilityTitle,
          body:
            !access && accessibilityRecoveryVisible
              ? t.accessibilityRecoveryCopy
              : t.accessibilityCopy,
          complete: access,
          action: accessibilityRequestAttempted ? "accessibility-settings" : "accessibility",
          label: accessibilityRequestAttempted ? t.accessibilitySettingsButton : t.accessibilityButton,
        })}
        ${stepCard({
          number: 2,
          title: t.passwordTitle,
          body: t.passwordCopy,
          complete: password,
          locked: !access,
          action: "password",
          label: t.passwordButton,
        })}
        ${stepCard({
          number: 3,
          title: t.automaticTitle,
          body: t.automaticCopy,
          complete: automatic,
          locked: !access || !password,
          dangerous: true,
          action: "enable",
          label: t.automaticButton,
          pendingLabel: t.finalStep,
        })}
      </div>
    </section>`;
}

function updateDescription() {
  const update = normalizeUpdateStatus(status.updateStatus);
  if (!update.configured || update.phase === "unconfigured") return t.updateUnavailable;
  if (update.errorCode) return updateErrorMessage(update.errorCode);
  if (update.phase === "checking") return t.updateChecking;
  if (update.phase === "up_to_date") return t.updateCurrent;
  if (update.phase === "available") return t.updateAvailable(escapeHtml(update.version || ""));
  if (update.phase === "downloading") {
    return t.updateDownloading(update.version ? escapeHtml(update.version) : null);
  }
  if (update.phase === "ready") {
    return t.updateReady(update.version ? escapeHtml(update.version) : null);
  }
  if (update.phase === "installing") return t.updateInstalling;
  if (update.phase === "error") return updateErrorMessage(update.errorCode);
  return t.updateAutomatic;
}

function updateAvailableVersion() {
  const update = normalizeUpdateStatus(status.updateStatus);
  return updateIsInstallable(update) ? update.version : null;
}

function updateErrorMessage(code) {
  switch (code) {
    case "unavailable":
      return t.updateUnavailable;
    case "busy":
      return t.updateBusy;
    case "version_changed":
      return t.updateVersionChanged;
    case "manual_update_required":
      return t.updateManualRequired;
    case "not_installed":
      return t.updateNotInstalled;
    case "auth_dialog_active":
      return t.updateAuthDialogActive;
    case "auth_dialog_check_failed":
      return t.updateAuthDialogCheckFailed;
    case "check_failed":
      return t.updateCheckFailed;
    case "download_failed":
      return t.updateDownloadFailed;
    case "install_failed":
      return t.updateInstallFailed;
    case "watcher_stop_failed":
      return t.updateWatcherStopFailed;
    case "watcher_restore_failed":
      return t.updateWatcherRestoreFailed;
    default:
      return t.updateError;
  }
}

function renderDashboard() {
  const active = status.automaticActive;
  const available = updateAvailableVersion();
  const update = normalizeUpdateStatus(status.updateStatus);
  const updateBusy = updateActionInProgress(update);
  app.innerHTML = `
    <section class="shell">
      ${brand(status.version)}
      <p class="eyebrow">${t.dashboardEyebrow}</p>
      <section class="status-hero">
        <div>
          <div class="status-kicker">OsaGuard</div>
          <h1 class="status-title">${active ? t.activeTitle : t.pausedTitle}</h1>
          <p class="status-copy">${active ? t.activeCopy : t.pausedCopy}</p>
        </div>
        <div class="status-dot ${active ? "" : "paused"}" aria-hidden="true"></div>
        <button class="button ${active ? "secondary" : ""}" data-action="toggle">${active ? t.pause : t.resume}</button>
      </section>
      <div class="dashboard-grid">
        <article class="panel">
          <div class="panel-label">${t.accessibilityPanel}</div>
          <div class="panel-value">${status.accessibilityGranted ? t.granted : t.missing}</div>
          <p class="panel-copy">${
            !status.accessibilityGranted && accessibilityRecoveryVisible
              ? t.accessibilityRecoveryCopy
              : t.accessibilityPanelCopy
          }</p>
          <div class="panel-actions">
            ${
              status.accessibilityGranted
                ? ""
                : `<button class="button secondary" data-action="${
                    accessibilityRequestAttempted
                      ? "accessibility-settings"
                      : "accessibility"
                  }">${
                    accessibilityRequestAttempted
                      ? t.accessibilitySettingsButton
                      : t.fix
                  }</button>`
            }
          </div>
        </article>
        <article class="panel">
          <div class="panel-label">${t.passwordPanel}</div>
          <div class="panel-value">${status.passwordSaved ? t.saved : t.notSaved}</div>
          <p class="panel-copy">${t.passwordPanelCopy}</p>
          <div class="panel-actions">
            <button class="button secondary" data-action="password" ${!status.installed || !status.accessibilityGranted ? "disabled" : ""}>${t.change}</button>
            <button class="button text" data-action="remove-password">${t.remove}</button>
          </div>
        </article>
        <article class="panel">
          <div class="panel-label">${t.updatePanel}</div>
          <div class="panel-value">${updateDescription()}</div>
          <p class="panel-copy">${t.updatePanelCopy}</p>
          <div class="panel-actions">
            <button class="button secondary" data-action="check-update" ${!update.configured || updateBusy ? "disabled" : ""}>${t.checkNow}</button>
            ${available ? `<button class="button" data-action="install-update" ${updateBusy ? "disabled" : ""}>${t.installUpdate(escapeHtml(available))}</button>` : ""}
          </div>
        </article>
      </div>
      <div class="danger-note"><strong>${t.securityNote}.</strong> ${t.permanentRisk}</div>
    </section>`;
}

function renderStartupError(error) {
  console.error("OsaGuard startup failed", error);
  app.innerHTML = `
    <section class="shell">
      ${brand(status?.version ?? "")}
      <div class="hero">
        <h1>${t.startupErrorTitle}</h1>
        <p class="hero-copy">${t.startupErrorCopy}</p>
        <button class="button primary" data-action="retry-startup" type="button">
          ${t.retry}
        </button>
      </div>
    </section>`;
}

function render() {
  if (!status) return;
  language = status.locale === "ru" ? "ru" : "en";
  t = copy[language];
  document.documentElement.lang = language;
  if (!status.installed) {
    renderInstall();
  } else if (!status.configured) {
    renderSetup();
  } else {
    renderDashboard();
  }
}

function showToast(message, error = false) {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("visible");
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 5200);
}

function errorMessage() {
  return t.genericError;
}

async function withBusy(operation, { onError = null } = {}) {
  if (busy) return;
  busy = true;
  document.body.classList.add("busy");
  render();
  try {
    await operation();
  } catch (error) {
    const message = onError ? await onError(error) : errorMessage(error);
    if (message) showToast(message, true);
  } finally {
    busy = false;
    document.body.classList.remove("busy");
    render();
  }
}

function openModal({ title, body, confirm, cancel = t.cancel, action }) {
  if (modal.open) {
    modalAction = null;
    modal.close();
  }
  modalTitle.textContent = title;
  modalBody.textContent = body;
  modalCancel.textContent = cancel;
  modalConfirm.textContent = confirm;
  modalAction = action;
  modal.showModal();
}

function openUninstallConfirmation() {
  openModal({
    title: t.uninstallTitle,
    body: t.uninstallBody,
    confirm: t.uninstallConfirm,
    action: async () => {
      await withBusy(
        async () => {
          await invoke("uninstall_app", {
            acknowledgement: "UNINSTALL_OSAGUARD",
          });
        },
        { onError: () => t.uninstallError },
      );
    },
  });
}

async function refreshStatus({ quiet = true, required = false } = {}) {
  try {
    status = await invoke("get_status");
    if (status.accessibilityGranted) {
      accessibilityRequestAttempted = false;
      accessibilityRecoveryVisible = false;
    }
    render();
  } catch (error) {
    if (!quiet) showToast(errorMessage(error), true);
    if (required) throw error;
  }
}

async function handleAction(action) {
  switch (action) {
    case "install":
      await withBusy(async () => {
        await invoke("install_app");
      });
      break;
    case "accessibility":
      await withBusy(async () => {
        status = await invoke("request_accessibility");
        if (!status.accessibilityGranted) {
          accessibilityRequestAttempted = true;
          accessibilityRecoveryVisible = true;
          showToast(t.accessFollowup);
        }
      });
      break;
    case "accessibility-settings":
      await withBusy(async () => {
        await invoke("open_accessibility_settings");
        accessibilityRequestAttempted = false;
        accessibilityRecoveryVisible = true;
        showToast(t.accessSettingsOpened);
      });
      break;
    case "password":
      await withBusy(
        async () => {
          const result = await invoke("store_password");
          const outcome = passwordOutcome(result);
          if (!outcome) throw new Error("invalid password action result");
          if (result.status) status = result.status;
          else await refreshStatus();
          if (outcome === "saved") showToast(t.passwordSavedToast);
        },
        { onError: () => t.passwordSaveError },
      );
      break;
    case "enable":
      openModal({
        title: t.riskTitle,
        body: t.riskBody,
        confirm: t.riskConfirm,
        cancel: t.notNow,
        action: async () => {
          await withBusy(async () => {
            status = await invoke("enable_automatic", {
              acknowledgement: "I_UNDERSTAND_PASSWORDLESS_ADMIN",
            });
            showToast(t.enabledToast);
          });
        },
      });
      break;
    case "toggle":
      await withBusy(async () => {
        const enabling = !status.automaticActive;
        status = await invoke("set_enabled", { enabled: enabling });
        showToast(enabling ? t.resumedToast : t.pausedToast);
      });
      break;
    case "remove-password":
      openModal({
        title: t.removeTitle,
        body: t.removeBody,
        confirm: t.removeConfirm,
        action: async () => {
          await withBusy(async () => {
            status = await invoke("forget_password", {
              confirmation: "REMOVE_SAVED_PASSWORD",
            });
            showToast(t.passwordRemovedToast);
          });
        },
      });
      break;
    case "check-update":
      await withBusy(
        async () => {
          await invoke("check_for_updates");
          await refreshStatus();
          const update = normalizeUpdateStatus(status.updateStatus);
          if (updateIsInstallable(update)) {
            showToast(t.updateAvailableToast(update.version));
          } else if (update.phase === "up_to_date") {
            showToast(t.upToDateToast);
          }
        },
        {
          onError: async () => {
            await refreshStatus();
            return updateErrorMessage(
              normalizeUpdateStatus(status?.updateStatus).errorCode,
            );
          },
        },
      );
      break;
    case "install-update": {
      const expectedVersion = normalizeUpdateStatus(
        status?.updateStatus,
      ).version;
      if (!expectedVersion) break;
      openModal({
        title: t.updateTitle,
        body: t.updateBody,
        confirm: t.updateConfirm,
        action: async () => {
          await withBusy(
            async () => {
              await invoke("install_update", {
                expectedVersion,
                acknowledgement: "INSTALL_SIGNED_UPDATE",
              });
            },
            {
              onError: async () => {
                await refreshStatus();
                return updateErrorMessage(
                  normalizeUpdateStatus(status?.updateStatus).errorCode,
                );
              },
            },
          );
        },
      });
      break;
    }
    case "retry-startup":
      window.location.reload();
      break;
    default:
      break;
  }
}

app.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button || button.disabled) return;
  handleAction(button.dataset.action);
});

modalCancel.addEventListener("click", () => {
  modalAction = null;
  modal.close();
});

modalConfirm.addEventListener("click", async () => {
  const action = modalAction;
  modalAction = null;
  modal.close();
  if (action) await action();
});

modal.addEventListener("cancel", () => {
  modalAction = null;
});

async function poll() {
  await refreshStatus();
  const delay = status?.configured ? 15000 : 3000;
  window.setTimeout(poll, delay);
}

await bootstrapRuntime({
  loadStatus: () => refreshStatus({ quiet: false, required: true }),
  subscribe: listen,
  subscriptions: [
    {
      event: "password-action-error",
      handler: () => showToast(t.passwordSaveError, true),
    },
    {
      event: "runtime-action-error",
      handler: () => showToast(t.runtimeActionError, true),
    },
    {
      event: "uninstall-requested",
      handler: openUninstallConfirmation,
    },
    {
      event: "install-update-requested",
      handler: () => handleAction("install-update"),
    },
  ],
  onReady: () => window.setTimeout(poll, 3000),
  onError: renderStartupError,
});
