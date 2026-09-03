// Frame capture driven by narration timing (episode: NetPulse promo).
// Reads narr1/narr_meta.json so scene cuts land exactly on voiceover segment starts.
// Usage:
//   node capture.mjs preview   -> grab a few key frames into preview/
//   node capture.mjs           -> full render into frames/
import puppeteer from "file:///C:/Users/henu_09/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EXE = "C:/Users/henu_09/.cache/puppeteer/chrome-headless-shell/win64-141.0.7390.78/chrome-headless-shell-win64/chrome-headless-shell.exe";
const BASE = __dirname;
const HTML = path.join(BASE, "index.html");
const META = JSON.parse(fs.readFileSync(path.join(BASE, "narr1", "narr_meta.json"), "utf8"));

const PREVIEW = process.argv[2] === "preview";
const OUTDIR = path.join(BASE, PREVIEW ? "preview" : "frames");
const FPS = 30;
const MARKERS = META.markers;
const TOTAL = META.total;
const W = 1280, H = 720;

(async () => {
  fs.mkdirSync(OUTDIR, { recursive: true });
  console.log("LAUNCHING browser...");
  const browser = await puppeteer.launch({
    executablePath: EXE,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--hide-scrollbars",
      "--force-color-profile=srgb",
      "--enable-unsafe-swiftshader",
      "--disable-features=Translate",
    ],
  });
  console.log("BROWSER up");
  const page = await browser.newPage();
  await page.setViewport({ width: W, height: H, deviceScaleFactor: 1 });
  page.on("pageerror", (e) => console.log("PAGEERR", e.message));
  page.on("requestfailed", (r) => console.log("REQFAIL", r.url(), r.failure() && r.failure().errorText));
  page.on("console", (m) => { if (m.type() === "error") console.log("CONSOLE_ERR", m.text()); });

  await page.evaluateOnNewDocument((mk, t, cs) => {
    window.__MARKERS = mk;
    window.__TOTAL = t;
    window.__CTA_START = cs;
  }, MARKERS, TOTAL, META.cta_start);

  await page.goto("file:///" + HTML.replace(/\\/g, "/"), { waitUntil: "load", timeout: 60000 });
  console.log("PAGE loaded");

  const ready = await page.evaluate(() => !!(window.__timelines && window.__timelines["main"] && window.__timelines["main"].duration() > 0));
  if (!ready) throw new Error("timeline not registered in main world");
  console.log("TIMELINE ready, duration=", await page.evaluate(() => window.__timelines["main"].duration()));

  await page.evaluate(() => (document.fonts ? document.fonts.ready : Promise.resolve()));
  await page.evaluate(() => { const tl = window.__timelines["main"]; tl.pause(); tl.seek(0); });
  await page.evaluate(() => { void document.body.offsetHeight; });

  if (PREVIEW) {
    const shots = [];
    for (let k = 0; k < MARKERS.length; k++) {
      const next = k + 1 < MARKERS.length ? MARKERS[k + 1] : TOTAL;
      shots.push({ name: `s${k + 1}_mid`, t: MARKERS[k] + (next - MARKERS[k]) * 0.55 });
    }
    shots.push({ name: "cta", t: META.cta_start + 3 });
    for (const s of shots) {
      await page.evaluate((tt) => { window.__timelines["main"].seek(tt); return tt; }, s.t);
      await page.evaluate(() => { void document.body.offsetHeight; });
      await page.screenshot({ path: path.join(OUTDIR, `${s.name}.png`), type: "png" });
      console.log(`shot ${s.name} @ ${s.t.toFixed(2)}s`);
    }
    console.log("PREVIEW_DONE");
  } else {
    const TOTAL_FRAMES = Math.round(TOTAL * FPS);
    console.log("CAPTURE start, frames=" + TOTAL_FRAMES + " duration=" + TOTAL);
    for (let i = 0; i < TOTAL_FRAMES; i++) {
      const t = i / FPS;
      await page.evaluate((tt) => { window.__timelines["main"].seek(tt); return tt; }, t);
      await page.evaluate(() => { void document.body.offsetHeight; });
      const pad = String(i).padStart(5, "0");
      await page.screenshot({ path: path.join(OUTDIR, `frame_${pad}.png`), type: "png" });
      if (i % 200 === 0 || i === TOTAL_FRAMES - 1) {
        console.log(`frame ${i}/${TOTAL_FRAMES} t=${t.toFixed(2)}s`);
      }
    }
    console.log("CAPTURE_DONE total=" + TOTAL);
  }

  try { await browser.close(); } catch (e) {}
  try { if (browser.process()) browser.process().kill("SIGKILL"); } catch (e) {}
  setTimeout(() => process.exit(0), 200);
})().catch((e) => {
  console.error("FATAL", e && e.stack ? e.stack : e);
  process.exit(1);
});
