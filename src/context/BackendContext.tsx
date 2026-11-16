import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { io } from 'socket.io-client';
import {
  API_BASE_URL,
  api,
  type AlertEntry,
  type ScanState,
  type Settings,
  type TrustedAp,
} from '../lib/api';
import { percentToDbm, toNetwork } from '../lib/adapt';
import type { Network, NetworkStatus, Observation } from '../data/types';

interface BackendContextValue {
  networks: Network[];
  lastScanAt: string | null;
  scanning: boolean;
  /** True while the SocketIO link to the Flask backend is up. */
  connected: boolean;
  trusted: TrustedAp[];
  settings: Settings | null;
  alerts: AlertEntry[];
  refreshAlerts: () => void;
  trustNetwork: (ssid: string, bssid: string) => Promise<void>;
  untrustNetwork: (ssid: string, bssid: string) => Promise<void>;
  toggleScanning: () => Promise<void>;
  saveSettings: (next: Settings) => Promise<void>;
  clearAlerts: () => Promise<void>;
  /** Desktop (browser) notifications on new Suspicious/Rogue detections. */
  desktopNotificationsEnabled: boolean;
  setDesktopNotificationsEnabled: (enabled: boolean) => Promise<void>;
  /** The browser's actual Notification permission state, so the UI can
   * explain why notifications aren't firing even though the setting is on
   * (e.g. the user denied the browser's permission prompt). 'unsupported'
   * when this browser has no Notification API at all. */
  notificationPermission: NotificationPermission | 'unsupported';
  soundAlertsEnabled: boolean;
  setSoundAlertsEnabled: (enabled: boolean) => void;
}

const BackendContext = createContext<BackendContextValue | null>(null);

const MAX_OBSERVATIONS = 15;
const LS_DESKTOP_NOTIFICATIONS = 'wifiguard.notifications.desktop';
const LS_SOUND_ALERTS = 'wifiguard.notifications.sound';

function readBoolPref(key: string, fallback: boolean): boolean {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : raw === 'true';
  } catch {
    return fallback;
  }
}

function writeBoolPref(key: string, value: boolean): void {
  try {
    localStorage.setItem(key, String(value));
  } catch {
    // localStorage can throw in private-browsing/storage-restricted modes;
    // the preference just won't persist across reloads, which is fine.
  }
}

/** Short, distinct two-tone alert beep, synthesized with the Web Audio API
 * so there's no audio asset to ship or fail to load. */
function playAlertSound(): void {
  try {
    const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const playTone = (freq: number, startAt: number, duration: number) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, ctx.currentTime + startAt);
      gain.gain.exponentialRampToValueAtTime(0.2, ctx.currentTime + startAt + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + startAt + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(ctx.currentTime + startAt);
      osc.stop(ctx.currentTime + startAt + duration + 0.02);
    };
    playTone(880, 0, 0.12);
    playTone(660, 0.14, 0.16);
    // Let the context close itself once the tones finish playing.
    setTimeout(() => void ctx.close(), 500);
  } catch {
    // Non-fatal: the detection and the desktop notification still worked.
  }
}

function notificationSupport(): NotificationPermission | 'unsupported' {
  if (typeof window === 'undefined' || !('Notification' in window)) return 'unsupported';
  return Notification.permission;
}

interface History {
  signal: number;
  channel: number;
  observations: Observation[];
}

export function BackendProvider({ children }: { children: ReactNode }) {
  const [scan, setScan] = useState<ScanState>({
    networks: [],
    last_scan: null,
    last_scan_at: null,
    scanning: true,
  });
  const [connected, setConnected] = useState(false);
  const [trusted, setTrusted] = useState<TrustedAp[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const historyRef = useRef<Map<string, History>>(new Map());

  // The stored preference alone isn't enough to decide the checkbox's
  // initial state: modern browsers (Chrome in particular) flatly refuse to
  // grant Notification permission from a request that isn't triggered by a
  // direct user gesture, so an auto-request on mount frequently can't
  // succeed at all. If the checkbox started "on" whenever the stored
  // preference was true regardless of actual permission, a user's first
  // click (meaning to turn it ON) would instead UNCHECK it, since React
  // sees it as already checked. So: only show it as on when permission is
  // ACTUALLY granted already; otherwise it starts unchecked no matter what
  // was stored, and the user's click is a genuine "turn on" gesture that
  // can reliably request permission.
  const [desktopNotificationsEnabled, setDesktopNotificationsEnabledState] = useState(
    () => readBoolPref(LS_DESKTOP_NOTIFICATIONS, true) && notificationSupport() === 'granted',
  );
  const [soundAlertsEnabled, setSoundAlertsEnabledState] = useState(() =>
    readBoolPref(LS_SOUND_ALERTS, true),
  );
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission | 'unsupported'>(
    notificationSupport,
  );
  // bssid -> { status, lastNotifiedAt } — tracks the last status we alerted
  // on and when. A network that STAYS Rogue/Suspicious re-notifies every
  // ALERT_REPEAT_MS milliseconds so the user keeps getting reminded.
  // Entries are removed when the BSSID drops out of the live scan so a
  // BSSID that disappears and reappears counts as fresh again.
  const ALERT_REPEAT_MS = 30_000; // re-notify every 30 seconds
  const lastAlertedStatusRef = useRef<Map<string, { status: NetworkStatus; notifiedAt: number }>>(new Map());
  // Separate from the map above (and NOT cleared when it empties out
  // between tests) -- this just answers "has this tab ever processed a
  // scan before", purely to suppress a notification storm from whatever
  // was already Rogue/Suspicious the very first time the page loads.
  const hasProcessedFirstScanRef = useRef(false);

  // Fold each incoming scan into a per-network activity log (newest first),
  // so the inspector's "Recent Activity" reflects real changes between scans.
  const applyScan = useCallback((data: ScanState) => {
    const time = data.last_scan ?? '';
    for (const n of data.networks) {
      const dbm = percentToDbm(n.signal);
      const prev = historyRef.current.get(n.bssid);
      if (!prev) {
        historyRef.current.set(n.bssid, {
          signal: dbm,
          channel: n.channel,
          observations: [
            { timestamp: time, event: 'BSSID first seen', detail: n.bssid },
            { timestamp: time, event: 'Encryption', detail: n.encryption },
            { timestamp: time, event: 'Detected', detail: `Channel ${n.channel}` },
            { timestamp: time, event: 'Scan', detail: `Signal: ${dbm} dBm` },
          ],
        });
        continue;
      }
      const added: Observation[] = [];
      if (prev.channel !== n.channel) {
        added.push({ timestamp: time, event: 'Channel changed', detail: `${prev.channel} → ${n.channel}` });
      }
      if (prev.signal !== dbm) {
        added.push({ timestamp: time, event: 'Signal changed', detail: `${prev.signal} → ${dbm} dBm` });
      }
      if (added.length > 0) {
        prev.observations = [...added.reverse(), ...prev.observations].slice(0, MAX_OBSERVATIONS);
      }
      prev.signal = dbm;
      prev.channel = n.channel;
    }
    setScan(data);
  }, []);

  useEffect(() => {
    api.getNetworks().then(applyScan).catch(() => {});
    api.getTrusted().then(setTrusted).catch(() => {});
    api.getSettings().then(setSettings).catch(() => {});

    const socket = io(API_BASE_URL, { transports: ['websocket', 'polling'] });
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('update', (data: ScanState) => applyScan(data));
    return () => {
      socket.disconnect();
    };
  }, [applyScan]);

  // Sync polling directly aligned with scan interval for near real-time updates
  useEffect(() => {
    const sec = Math.max(1, parseInt(settings?.scan_interval || '3', 10));
    const timer = setInterval(() => {
      api.getNetworks().then(applyScan).catch(() => {});
    }, sec * 1000);
    return () => clearInterval(timer);
  }, [settings?.scan_interval, applyScan]);

  const networks = useMemo(() => {
    const now = Date.now();
    return scan.networks.map((raw) =>
      toNetwork(raw, trusted, historyRef.current.get(raw.bssid)?.observations ?? [], now),
    );
  }, [scan, trusted]);

  // Fire a desktop notification (and optional sound) the moment a network
  // TRANSITIONS into Suspicious/Rogue, and again every 30 s while it stays
  // there, so the user keeps getting reminded until the threat is gone.
  useEffect(() => {
    if (scan.last_scan_at === null) return;

    const seenBefore = hasProcessedFirstScanRef.current;
    const now = Date.now();
    for (const network of networks) {
      const prev = lastAlertedStatusRef.current.get(network.bssid);
      const isAlertStatus = network.status === 'rogue' || network.status === 'suspicious';
      const isNewStatus = isAlertStatus && prev?.status !== network.status && (seenBefore || prev !== undefined);
      const isRepeat = isAlertStatus && prev?.status === network.status && (now - (prev?.notifiedAt ?? 0)) >= 30_000;
      if (isNewStatus || isRepeat) {
        if (desktopNotificationsEnabled && notificationSupport() === 'granted') {
          const title = network.status === 'rogue' ? 'Rogue access point detected' : 'Suspicious access point detected';
          const body = [
            `${network.ssid} (${network.bssid})`,
            `Risk score: ${network.riskScore}/100`,
            network.reasons[0],
          ]
            .filter(Boolean)
            .join('\n');
          try {
            new Notification(title, {
              body,
              tag: `${network.bssid}:${network.status}`,
              requireInteraction: true,
            });
          } catch {
            // Non-fatal; sound alert still fires.
          }
        }
        if (soundAlertsEnabled) playAlertSound();
        lastAlertedStatusRef.current.set(network.bssid, { status: network.status, notifiedAt: now });
      } else if (!prev || prev.status !== network.status) {
        // Status changed to a non-alert state — track it silently.
        lastAlertedStatusRef.current.set(network.bssid, { status: network.status, notifiedAt: 0 });
      }
    }

    // A BSSID that drops out of the scan entirely (Stop Attack / Restore
    // Networking makes it vanish, not just change status) forgets its last
    // status, so the NEXT time it reappears — e.g. the next test launched —
    // counts as a fresh transition and notifies again. Without this, a
    // BSSID that was Rogue once stays "already alerted" for the rest of
    // the session even after it's gone and come back, which is why running
    // several tests back to back (Test 1/2/3 all broadcast from this
    // machine's same real MAC) only ever notified on the very first one.
    const currentBssids = new Set(networks.map((n) => n.bssid));
    for (const bssid of lastAlertedStatusRef.current.keys()) {
      if (!currentBssids.has(bssid)) lastAlertedStatusRef.current.delete(bssid);
    }
    hasProcessedFirstScanRef.current = true;
  }, [networks, scan.last_scan_at, desktopNotificationsEnabled, soundAlertsEnabled]);

  const refreshAlerts = useCallback(() => {
    api.getAlerts().then(setAlerts).catch(() => {});
  }, []);

  const setDesktopNotificationsEnabled = useCallback(async (enabled: boolean) => {
    if (!enabled) {
      setDesktopNotificationsEnabledState(false);
      writeBoolPref(LS_DESKTOP_NOTIFICATIONS, false);
      return;
    }
    if (notificationSupport() === 'unsupported') {
      // Nothing to request; leave the setting off since it can't work here.
      setDesktopNotificationsEnabledState(false);
      writeBoolPref(LS_DESKTOP_NOTIFICATIONS, false);
      return;
    }
    // Requesting permission needs a user gesture (this is called from a
    // checkbox's onChange, which qualifies) and must be re-requested if the
    // user previously denied it — the browser remembers that decision.
    const permission = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
    setNotificationPermission(permission);
    const granted = permission === 'granted';
    setDesktopNotificationsEnabledState(granted);
    writeBoolPref(LS_DESKTOP_NOTIFICATIONS, granted);
  }, []);

  const setSoundAlertsEnabled = useCallback((enabled: boolean) => {
    setSoundAlertsEnabledState(enabled);
    writeBoolPref(LS_SOUND_ALERTS, enabled);
  }, []);

  const value: BackendContextValue = {
    networks,
    lastScanAt: scan.last_scan_at,
    scanning: scan.scanning,
    connected,
    trusted,
    settings,
    alerts,
    refreshAlerts,
    trustNetwork: async (ssid, bssid) => setTrusted(await api.addTrusted(ssid, bssid)),
    untrustNetwork: async (ssid, bssid) => setTrusted(await api.removeTrusted(ssid, bssid)),
    toggleScanning: async () => {
      const res = await api.setScanning(!scan.scanning);
      setScan((s) => ({ ...s, scanning: res.scanning }));
    },
    saveSettings: async (next) => setSettings(await api.updateSettings(next)),
    clearAlerts: async () => setAlerts(await api.clearAlerts()),
    desktopNotificationsEnabled,
    setDesktopNotificationsEnabled,
    notificationPermission,
    soundAlertsEnabled,
    setSoundAlertsEnabled,
  };

  return <BackendContext.Provider value={value}>{children}</BackendContext.Provider>;
}

export function useBackend(): BackendContextValue {
  const ctx = useContext(BackendContext);
  if (!ctx) throw new Error('useBackend must be used inside <BackendProvider>');
  return ctx;
}
