/* eslint-disable @typescript-eslint/no-explicit-any */
import type { PageScan } from "@steplight/core";

/** Name of the Playwright binding the injected script reports through. */
export const BINDING_NAME = "__steplightEmit";

/**
 * A page scan taken inside the page. `load` = the document finished loading, `rescan` = text that was
 * not there at load time appeared about a second later (late injection), `spa` = a client-side route change.
 */
export interface ScanEvent {
  type: "scan";
  reason: "load" | "rescan" | "spa";
  scan: PageScan;
}

/** An interaction reported by the injected page script. */
export interface PageEvent {
  type: "click" | "change" | "submit";
  selector: string;
  text: string;
  /** Present for `submit`. */
  method?: string;
  action?: string;
  body?: string;
}

/**
 * Page-side script: reports clicks, field changes and form submissions through the
 * binding. Self-contained (serialised by Playwright). Never throws into the host page.
 * Password, payment-card, OTP and similar field values are never read (see neverCapture.ts); file fields neither.
 */
export function installPageListeners(bindingName: string): void {
  const w: any = globalThis;
  if (w.__steplightInstalled) return;
  w.__steplightInstalled = true;
  const emit = (e: unknown) => {
    try {
      const fn = w[bindingName];
      if (typeof fn === "function") void Promise.resolve(fn(e)).catch(() => undefined);
    } catch {
      /* fail open */
    }
  };
  // "Never capture" rule (always on): mirrors core/neverCapture.ts (kept in sync by a test);
  // repeated here because this function is serialised into the page.
  const NEVER_NAME = /(^|[^a-z0-9])(card|cc|cvv|cvc|csc|otp|pin|ssn|aadhaar|aadhar|pan|passcode|password|passwd|pwd|iban|secret|token|csrf)\d{0,2}([^a-z0-9]|$)|cardnum|creditcard|ccnum|cvv2|cardno|panno|aadhaarno/i;
  const NEVER_AUTO = /(^|\s)(cc-[a-z-]+|one-time-code|current-password|new-password)(\s|$)/i;
  const neverField = (e: any): boolean => {
    if (!e || !e.tagName) return false;
    const tag = String(e.tagName).toLowerCase();
    if (!(tag === "input" || tag === "textarea" || tag === "select" || e.isContentEditable === true)) return false;
    if (String(e.type || "").toLowerCase() === "password") return true;
    if (NEVER_AUTO.test(String(e.getAttribute("autocomplete") || ""))) return true;
    const words = [e.name, e.id, e.getAttribute("aria-label"), e.getAttribute("placeholder")]
      .filter(Boolean)
      .map((v: any) => String(v).replace(/([a-z0-9])([A-Z])/g, "$1_$2"))
      .join(" ");
    return words !== "" && NEVER_NAME.test(words);
  };
  const selectorOf = (el: any): string => {
    if (!el || !el.tagName) return "";
    const tag = String(el.tagName).toLowerCase();
    if (el.id) return `${tag}#${el.id}`;
    const name = el.getAttribute && el.getAttribute("name");
    if (name) return `${tag}[name="${name}"]`;
    const cls = typeof el.className === "string" ? el.className.trim().split(/\s+/)[0] : "";
    return cls ? `${tag}.${cls}` : tag;
  };
  const textOf = (el: any): string => {
    const isButtonInput = String(el.tagName).toLowerCase() === "input" && /^(button|submit|reset|image)$/i.test(String(el.type || ""));
    const t =
      (el.getAttribute && (el.getAttribute("aria-label") || el.getAttribute("title"))) ||
      (neverField(el) ? "" : el.innerText) ||
      (isButtonInput ? el.value : "") ||
      (neverField(el) ? "" : el.textContent) ||
      "";
    return String(t).replace(/\s+/g, " ").trim().slice(0, 200);
  };
  const labelOf = (el: any): string =>
    String(
      (el.labels && el.labels[0] && el.labels[0].textContent) ||
        el.getAttribute("aria-label") ||
        el.getAttribute("placeholder") ||
        el.name ||
        el.id ||
        el.tagName,
    )
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 100);
  const formBody = (form: any): string => {
    const parts: string[] = [];
    for (const el of Array.from(form.elements) as any[]) {
      if (!el.name || el.disabled) continue;
      const type = String(el.type || "").toLowerCase();
      if ((type === "checkbox" || type === "radio") && !el.checked) continue;
      if (type === "submit" || type === "button" || type === "file") continue;
      if (neverField(el)) continue; // never read, not even the name
      parts.push(`${encodeURIComponent(el.name)}=${encodeURIComponent(String(el.value ?? ""))}`);
    }
    return parts.join("&");
  };
  const submitEvent = (form: any) => {
    emit({
      type: "submit",
      selector: selectorOf(form),
      text: textOf(form).slice(0, 100),
      method: String(form.method || "get").toUpperCase(),
      action: String(form.action || w.location.href),
      body: formBody(form),
    });
  };

  w.document.addEventListener(
    "click",
    (ev: any) => {
      try {
        const t = ev.target;
        const el = (t && t.closest && t.closest("a,button,input,select,summary,[role=button],label")) || t;
        if (el) emit({ type: "click", selector: selectorOf(el), text: textOf(el) });
      } catch {
        /* fail open */
      }
    },
    true,
  );
  w.document.addEventListener(
    "change",
    (ev: any) => {
      try {
        const el = ev.target;
        if (!el || !el.tagName) return;
        emit({ type: "change", selector: selectorOf(el), text: labelOf(el) });
      } catch {
        /* fail open */
      }
    },
    true,
  );
  w.document.addEventListener(
    "submit",
    (ev: any) => {
      try {
        submitEvent(ev.target);
      } catch {
        /* fail open */
      }
    },
    true,
  );
  try {
    const proto: any = (globalThis as any).HTMLFormElement.prototype;
    const original = proto.submit;
    proto.submit = function (this: any, ...args: unknown[]) {
      try {
        submitEvent(this);
      } catch {
        /* fail open */
      }
      return original.apply(this, args);
    };
  } catch {
    /* fail open */
  }
}

/**
 * Page-side script: scans the page when it has loaded, again after a second if text it had not
 * contained appears (late injection), and after a client-side route change (`history.pushState`,
 * `replaceState`, `popstate`, `hashchange`), and reports each scan through the binding. Scanning
 * happens inside the page so an agent that navigates away immediately cannot race the snapshot.
 * Self-contained (serialised into spec/page-scan.js); `scan` is `collectPageScan`.
 */
export function installScanning(bindingName: string, scan: () => unknown): void {
  const w: any = globalThis;
  if (w.__steplightScanning) return;
  w.__steplightScanning = true;
  const RESCAN_MS = 1000;
  const ROUTE_DEBOUNCE_MS = 300;
  const seen = new Set<string>();
  let lastHref = "";
  let routeTimer: any;
  const send = (reason: string, result: unknown): void => {
    try {
      const fn = w[bindingName];
      if (typeof fn === "function") void Promise.resolve(fn({ type: "scan", reason, scan: result })).catch(() => undefined);
    } catch {
      /* fail open */
    }
  };
  const rescan = (): void => {
    try {
      if (String(w.location.href) !== lastHref) return; // the route changed meanwhile: its own scan covers it
      const result: any = scan();
      const fresh = result.dom.nodes.filter((n: any) => !seen.has(n.text) && String(n.text).length >= 8);
      if (fresh.length === 0) return;
      for (const n of result.dom.nodes) seen.add(n.text);
      send("rescan", result);
    } catch {
      /* fail open */
    }
  };
  const take = (reason: string): void => {
    try {
      const result: any = scan();
      lastHref = String(w.location.href);
      seen.clear();
      for (const n of result.dom.nodes) seen.add(n.text);
      send(reason, result);
      setTimeout(rescan, RESCAN_MS);
    } catch {
      /* fail open */
    }
  };
  const routeChanged = (): void => {
    try {
      if (String(w.location.href) === lastHref) return;
      clearTimeout(routeTimer);
      routeTimer = setTimeout(() => take("spa"), ROUTE_DEBOUNCE_MS);
    } catch {
      /* fail open */
    }
  };
  try {
    for (const name of ["pushState", "replaceState"]) {
      const original = w.history[name];
      // A Proxy keeps the native name, length and toString() of the method the page sees.
      w.history[name] = new Proxy(original, {
        apply(target: any, thisArg: any, args: any[]) {
          const result = Reflect.apply(target, thisArg, args);
          routeChanged();
          return result;
        },
      });
    }
    w.addEventListener("popstate", routeChanged);
    w.addEventListener("hashchange", routeChanged);
  } catch {
    /* fail open */
  }
  if (w.document.readyState === "complete") take("load");
  else w.addEventListener("load", () => take("load"), { once: true });
}
