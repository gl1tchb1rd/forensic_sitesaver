# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import webbrowser
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from common import APP_NAME, APP_VERSION, DISCLAIMER, REPOSITORY_URL

TECH_DIR = Path(__file__).resolve().parent
PUBLIC_ROOT = TECH_DIR.parent
CLI = TECH_DIR / "cli.py"


def open_path(path: Path) -> None:
    path = path.resolve()
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        messagebox.showerror("Öffnen fehlgeschlagen", str(exc))


class Runner:
    def __init__(self, app: "App") -> None:
        self.app = app
        self.process: subprocess.Popen[str] | None = None
        self.stop_requested = False

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, args: list[str], title: str) -> None:
        if self.running:
            messagebox.showwarning("Vorgang läuft", "Es läuft bereits ein Vorgang.")
            return
        self.stop_requested = False
        self.app.clear_log()
        self.app.append_log(f"{title}\n{'=' * 78}\n")
        self.app.set_running(True)
        cmd = [sys.executable, "-u", str(CLI), *args]

        def worker() -> None:
            try:
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                self.process = subprocess.Popen(
                    cmd, cwd=str(PUBLIC_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace", bufsize=1,
                    creationflags=flags,
                )
                assert self.process.stdout is not None
                for line in self.process.stdout:
                    self.app.events.put(("log", line))
                    if line.startswith("ERGEBNIS_ORDNER="):
                        self.app.events.put(("result", line.split("=", 1)[1].strip()))
                rc = self.process.wait()
                self.app.events.put(("done", (rc, self.stop_requested)))
            except Exception as exc:
                self.app.events.put(("log", f"\nFEHLER beim Prozessstart: {exc}\n"))
                self.app.events.put(("done", (-1, self.stop_requested)))
            finally:
                self.process = None
        threading.Thread(target=worker, daemon=True).start()

    def stop(self) -> None:
        if not self.running or self.process is None:
            return
        self.stop_requested = True
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        except Exception as exc:
            self.app.append_log(f"Abbruchfehler: {exc}\n")


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1120x850")
        self.minsize(980, 720)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.runner = Runner(self)
        self.last_result: Path | None = None
        self._style()
        self._header()
        self._tabs()
        self._log()
        self._status()
        self.after(100, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _style(self) -> None:
        s = ttk.Style(self)
        if "clam" in s.theme_names():
            try: s.theme_use("clam")
            except tk.TclError: pass
        s.configure("Title.TLabel", font=("TkDefaultFont", 17, "bold"))
        s.configure("Hint.TLabel", foreground="#444444")
        s.configure("Section.TLabelframe.Label", font=("TkDefaultFont", 10, "bold"))

    def _header(self) -> None:
        f = ttk.Frame(self, padding=(14, 12, 14, 8)); f.pack(fill="x")
        ttk.Label(f, text=f"{APP_NAME} {APP_VERSION}", style="Title.TLabel").pack(anchor="w")
        ttk.Label(f, text="Passive Website-Sicherung, HAR-Auswertung und eigenständige Domain-/Hosting-/MX-Analyse.", style="Hint.TLabel").pack(anchor="w", pady=(3,0))

    def _tabs(self) -> None:
        self.tabs = ttk.Notebook(self); self.tabs.pack(fill="x", padx=14, pady=(0,8))
        self.t_capture = ttk.Frame(self.tabs, padding=12)
        self.t_domain = ttk.Frame(self.tabs, padding=12)
        self.t_har = ttk.Frame(self.tabs, padding=12)
        self.t_origin = ttk.Frame(self.tabs, padding=12)
        self.t_export = ttk.Frame(self.tabs, padding=12)
        self.t_update = ttk.Frame(self.tabs, padding=12)
        self.t_about = ttk.Frame(self.tabs, padding=12)
        for frame, title in [
            (self.t_capture,"Website-Sicherung"),(self.t_domain,"Domain-Analyse"),(self.t_har,"HAR-Analyse"),
            (self.t_origin,"Origin-IP ergänzen"),(self.t_export,"Berichte exportieren"),(self.t_update,"Updates"),(self.t_about,"Über"),
        ]:
            self.tabs.add(frame, text=title)
        self._capture_tab(); self._domain_tab(); self._har_tab(); self._origin_tab(); self._export_tab(); self._update_tab(); self._about_tab()

    def _entry(self, parent, row, label, var, browse=None):
        ttk.Label(parent, text=label).grid(row=row,column=0,sticky="w",padx=(0,10),pady=4)
        ttk.Entry(parent,textvariable=var).grid(row=row,column=1,sticky="ew",pady=4)
        if browse: ttk.Button(parent,text="Auswählen …",command=browse).grid(row=row,column=2,padx=(8,0),pady=4)
        parent.columnconfigure(1,weight=1)

    def _choose_dir(self,var):
        p=filedialog.askdirectory(initialdir=var.get() or str(PUBLIC_ROOT))
        if p: var.set(p)

    def _capture_tab(self):
        f=self.t_capture
        self.cap_url=tk.StringVar(); self.cap_out=tk.StringVar(value=str(PUBLIC_ROOT/"Sicherungen")); self.cap_browser=tk.StringVar(value="chromium")
        self.cap_headless=tk.BooleanVar(value=False); self.cap_max=tk.StringVar(value="1000"); self.cap_seg=tk.StringVar(value="20")
        self.cap_delay=tk.StringVar(value="500"); self.cap_timeout=tk.StringVar(value="30000"); self.cap_allow=tk.StringVar()
        self._entry(f,0,"Website / Domain:",self.cap_url)
        self._entry(f,1,"Sicherungsordner:",self.cap_out,lambda:self._choose_dir(self.cap_out))
        ttk.Label(f,text="Browser:").grid(row=2,column=0,sticky="w",pady=4)
        ttk.Combobox(f,textvariable=self.cap_browser,values=["chromium","firefox"],state="readonly",width=16).grid(row=2,column=1,sticky="w")
        ttk.Checkbutton(f,text="Headless",variable=self.cap_headless).grid(row=2,column=1,sticky="e")
        adv=ttk.LabelFrame(f,text="Crawl-Parameter",padding=10,style="Section.TLabelframe"); adv.grid(row=3,column=0,columnspan=3,sticky="ew",pady=(10,4))
        opts=[("Max. Seiten (0 = unbegrenzt)",self.cap_max),("Seiten je HAR-Segment",self.cap_seg),("Pause ms",self.cap_delay),("Timeout ms",self.cap_timeout)]
        for i,(label,var) in enumerate(opts):
            r,c=divmod(i,2); ttk.Label(adv,text=label).grid(row=r,column=c*2,sticky="w",padx=(0,7),pady=3); ttk.Entry(adv,textvariable=var,width=12).grid(row=r,column=c*2+1,sticky="w",padx=(0,22),pady=3)
        self._entry(f,4,"Zusätzlich erlaubte Hosts (Komma):",self.cap_allow)
        ttk.Label(f,text="Der Crawler klickt keine Links und sendet keine Formulare; aktive Navigation erfolgt nur passiv per GET.",style="Hint.TLabel").grid(row=5,column=0,columnspan=3,sticky="w",pady=(5,8))
        ttk.Button(f,text="Sicherung starten",command=self.start_capture).grid(row=6,column=0,sticky="w")
        ttk.Button(f,text="Ausgabeordner öffnen",command=lambda:open_path(Path(self.cap_out.get()))).grid(row=6,column=1,sticky="w")

    def _domain_tab(self):
        f=self.t_domain
        self.dom_value=tk.StringVar(); self.dom_out=tk.StringVar(value=str(PUBLIC_ROOT/"Domainanalysen")); self.dom_pdf=tk.BooleanVar(value=True)
        self._entry(f,0,"Domain / URL:",self.dom_value)
        self._entry(f,1,"Ausgabe-Elternordner:",self.dom_out,lambda:self._choose_dir(self.dom_out))
        ttk.Checkbutton(f,text="Direkt PDF-Aktenausfertigung erzeugen",variable=self.dom_pdf).grid(row=2,column=1,sticky="w",pady=5)
        ttk.Label(f,text="Analysiert DNS, Registrar/RDAP/WHOIS, Webserver/Hosting und besonders MX-/Mailserver-Infrastruktur inklusive Provider- und GeoIP-Hinweisen.",wraplength=900,style="Hint.TLabel").grid(row=3,column=0,columnspan=3,sticky="w",pady=(3,8))
        ttk.Button(f,text="Domain analysieren",command=self.start_domain).grid(row=4,column=0,sticky="w")

    def _har_tab(self):
        f=self.t_har
        self.har_in=tk.StringVar(); self.har_out=tk.StringVar(value=str(PUBLIC_ROOT/"HAR_Auswertungen")); self.har_base=tk.StringVar()
        ttk.Label(f,text="HAR-Datei / Segmentordner:").grid(row=0,column=0,sticky="w",padx=(0,10),pady=4)
        ttk.Entry(f,textvariable=self.har_in).grid(row=0,column=1,sticky="ew")
        bf=ttk.Frame(f); bf.grid(row=0,column=2,padx=(8,0)); ttk.Button(bf,text="Datei …",command=self._har_file).pack(side="left"); ttk.Button(bf,text="Ordner …",command=self._har_dir).pack(side="left",padx=4)
        f.columnconfigure(1,weight=1)
        self._entry(f,1,"Bezugs-URL (optional):",self.har_base)
        self._entry(f,2,"Ausgabeordner:",self.har_out,lambda:self._choose_dir(self.har_out))
        ttk.Button(f,text="HAR analysieren",command=self.start_har).grid(row=3,column=0,sticky="w",pady=(8,0))

    def _har_file(self):
        p=filedialog.askopenfilename(filetypes=[("HAR/ZIP","*.har *.zip"),("Alle Dateien","*.*")]);
        if p:self.har_in.set(p)
    def _har_dir(self):
        p=filedialog.askdirectory();
        if p:self.har_in.set(p)

    def _origin_tab(self):
        f=self.t_origin
        self.org_dir=tk.StringVar(); self.org_ips=tk.StringVar(); self.org_note=tk.StringVar()
        self._entry(f,0,"Domainanalyse-Ordner:",self.org_dir,lambda:self._choose_dir(self.org_dir))
        self._entry(f,1,"Bekannte Origin-/Server-IP(s):",self.org_ips)
        self._entry(f,2,"Quelle / Ermittlungsvermerk:",self.org_note)
        ttk.Label(f,text="Die IP wird nicht vom Programm als Origin ermittelt, sondern ausschließlich als manuell vorgegebener Befund gekennzeichnet und technisch angereichert.",wraplength=900,style="Hint.TLabel").grid(row=3,column=0,columnspan=3,sticky="w",pady=(4,8))
        ttk.Button(f,text="Origin-IP ergänzen",command=self.start_origin).grid(row=4,column=0,sticky="w")

    def _export_tab(self):
        f=self.t_export
        self.exp_source=tk.StringVar(); self.exp_out=tk.StringVar(); self.exp_combined=tk.BooleanVar(value=True)
        self._entry(f,0,"Sicherungs- oder Domainanalyse-Ordner:",self.exp_source,lambda:self._choose_dir(self.exp_source))
        self._entry(f,1,"Exportordner:",self.exp_out,lambda:self._choose_dir(self.exp_out))
        ttk.Checkbutton(f,text="Zusätzlich Sammel-PDF erzeugen",variable=self.exp_combined).grid(row=2,column=1,sticky="w",pady=5)
        ttk.Label(f,text="Der Export wird außerhalb des Primärordners erzeugt, damit dessen Prüfsummenbestand unverändert bleibt. Bei vorhandener manueller Origin-IP wird automatisch die kombinierte Domainanalyse verwendet.",wraplength=900,style="Hint.TLabel").grid(row=3,column=0,columnspan=3,sticky="w",pady=(4,8))
        ttk.Button(f,text="Berichte als PDF exportieren",command=self.start_export).grid(row=4,column=0,sticky="w")

    def _update_tab(self):
        f=self.t_update
        ttk.Label(f,text="Updates betreffen ausschließlich freigegebene Python-Abhängigkeiten und Playwright-Browser. Der Programmcode aktualisiert sich nicht selbst.",wraplength=900).grid(row=0,column=0,columnspan=3,sticky="w",pady=(0,10))
        ttk.Button(f,text="Auf Paketupdates prüfen",command=lambda:self.runner.start(["update","--check-only"],"Update-Prüfung")).grid(row=1,column=0,sticky="w")
        ttk.Button(f,text="Abhängigkeiten aktualisieren …",command=self.start_update).grid(row=1,column=1,sticky="w",padx=8)
        ttk.Button(f,text="Installierte Lizenzen neu erfassen",command=lambda:self.runner.start(["licenses"],"Lizenzinventar aktualisieren")).grid(row=1,column=2,sticky="w")

    def _about_tab(self):
        f=self.t_about
        text=(f"{APP_NAME} {APP_VERSION}\n\nProjekt / Quellcode: {REPOSITORY_URL}\n\nLizenz: GNU General Public License v3.0 oder später (GPL-3.0-or-later). "
              "Die Lizenz gestattet private, wissenschaftliche, behördliche und kommerzielle Nutzung nach ihren Bedingungen.\n\n"
              "Keine KI-/Cloud-Analyse: Das Programm überträgt keine HAR-Dateien, Screenshots oder Sicherungspakete an OpenAI, ChatGPT, Gemini oder andere KI-Dienste.\n\n"
              "DISCLAIMER\n"+DISCLAIMER)
        ttk.Label(f,text=text,wraplength=940,justify="left").pack(anchor="w")
        b=ttk.Frame(f); b.pack(fill="x",pady=(14,0))
        ttk.Button(b,text="GitHub-Repository",command=lambda:webbrowser.open(REPOSITORY_URL)).pack(side="left")
        ttk.Button(b,text="README öffnen",command=lambda:open_path(PUBLIC_ROOT/"README.md")).pack(side="left",padx=6)
        ttk.Button(b,text="GPL-Lizenz öffnen",command=lambda:open_path(TECH_DIR/"LICENSE_GPL-3.0.txt")).pack(side="left",padx=6)
        ttk.Button(b,text="Lizenz-/Drittanbieterhinweise",command=lambda:open_path(TECH_DIR/"LIZENZEN_UND_DRITTANBIETER.txt")).pack(side="left",padx=6)
        ttk.Button(b,text="Changelog",command=lambda:open_path(TECH_DIR/"CHANGELOG.md")).pack(side="left",padx=6)

    def _log(self):
        f=ttk.LabelFrame(self,text="Live-Protokoll",padding=8,style="Section.TLabelframe"); f.pack(fill="both",expand=True,padx=14,pady=(0,8))
        self.log=ScrolledText(f,height=18,wrap="word",font=("TkFixedFont",9)); self.log.pack(fill="both",expand=True)

    def _status(self):
        f=ttk.Frame(self,padding=(14,2,14,10)); f.pack(fill="x")
        self.progress=ttk.Progressbar(f,mode="indeterminate"); self.progress.pack(side="left",fill="x",expand=True)
        self.stop=ttk.Button(f,text="Vorgang abbrechen",command=self.runner.stop,state="disabled"); self.stop.pack(side="right",padx=(8,0))
        self.status=tk.StringVar(value="Bereit"); ttk.Label(f,textvariable=self.status).pack(side="right",padx=8)

    def clear_log(self): self.log.delete("1.0","end")
    def append_log(self,s): self.log.insert("end",s); self.log.see("end")
    def set_running(self,r):
        if r:self.progress.start(12);self.status.set("Vorgang läuft …");self.stop.config(state="normal")
        else:self.progress.stop();self.status.set("Bereit");self.stop.config(state="disabled")

    def _poll(self):
        try:
            while True:
                kind,payload=self.events.get_nowait()
                if kind=="log":self.append_log(str(payload))
                elif kind=="result":self.last_result=Path(str(payload)); self.status.set("Ergebnis verfügbar")
                elif kind=="done":
                    rc,stopped=payload; self.set_running(False)
                    if stopped:self.status.set("Abgebrochen");self.append_log("\nVorgang abgebrochen.\n")
                    elif rc==0:self.status.set("Erfolgreich abgeschlossen");self.append_log("\nVorgang erfolgreich abgeschlossen.\n")
                    else:self.status.set(f"Fehler ({rc})");self.append_log(f"\nVorgang mit Rückgabecode {rc} beendet.\n")
        except queue.Empty:pass
        self.after(100,self._poll)

    def _ints(self):
        try:return int(self.cap_max.get()),int(self.cap_seg.get()),int(self.cap_delay.get()),int(self.cap_timeout.get())
        except ValueError:raise ValueError("Crawl-Parameter müssen ganze Zahlen sein.")

    def start_capture(self):
        if not self.cap_url.get().strip():return messagebox.showerror("Fehlende URL","Bitte Website/Domain eingeben.")
        try:maxp,seg,delay,to=self._ints()
        except ValueError as e:return messagebox.showerror("Einstellung",str(e))
        args=["capture",self.cap_url.get().strip(),"--output",self.cap_out.get(),"--browser",self.cap_browser.get(),"--max-pages",str(maxp),"--segment-pages",str(seg),"--delay-ms",str(delay),"--timeout-ms",str(to)]
        if self.cap_headless.get():args.append("--headless")
        for h in self.cap_allow.get().split(","):
            if h.strip():args += ["--allow-host",h.strip()]
        self.runner.start(args,"Website-Sicherung")

    def start_domain(self):
        if not self.dom_value.get().strip():return messagebox.showerror("Fehlende Domain","Bitte Domain/URL eingeben.")
        args=["domain",self.dom_value.get().strip(),"--output",self.dom_out.get()]
        if self.dom_pdf.get():args.append("--pdf")
        self.runner.start(args,"Eigenständige Domain-/Hosting-/MX-Analyse")

    def start_har(self):
        if not self.har_in.get().strip():return messagebox.showerror("Fehlende HAR","Bitte HAR-Datei oder Segmentordner auswählen.")
        args=["har",self.har_in.get(),"--output",self.har_out.get()]
        if self.har_base.get().strip():args += ["--base-url",self.har_base.get().strip()]
        self.runner.start(args,"HAR-Analyse")

    def start_origin(self):
        if not self.org_dir.get().strip() or not self.org_ips.get().strip():return messagebox.showerror("Fehlende Angaben","Domainanalyse-Ordner und IP sind erforderlich.")
        self.runner.start(["origin","--domain-dir",self.org_dir.get(),"--ips",self.org_ips.get(),"--note",self.org_note.get()],"Origin-/Server-IP-Ergänzung")

    def start_export(self):
        if not self.exp_source.get().strip():return messagebox.showerror("Fehlende Quelle","Bitte Sicherungs-/Domainanalyse-Ordner auswählen.")
        src=Path(self.exp_source.get()).resolve()
        if not self.exp_out.get().strip():self.exp_out.set(str(src.parent/(src.name+"_Aktenexport")))
        args=["export","--source",str(src),"--output",self.exp_out.get()]
        if not self.exp_combined.get():args.append("--no-combined")
        self.runner.start(args,"PDF-Aktenexport")

    def start_update(self):
        if messagebox.askyesno("Abhängigkeiten aktualisieren","Freigegebene Python-Abhängigkeiten und Playwright-Browser aktualisieren?\n\nDer Programmcode selbst wird nicht ersetzt."):
            self.runner.start(["update","--yes"],"Abhängigkeiten aktualisieren")

    def _close(self):
        if self.runner.running and not messagebox.askyesno("Vorgang läuft","Laufenden Vorgang abbrechen und Programm schließen?"):return
        if self.runner.running:self.runner.stop()
        self.destroy()


def main() -> int:
    app=App(); app.mainloop(); return 0

if __name__=="__main__":
    raise SystemExit(main())
