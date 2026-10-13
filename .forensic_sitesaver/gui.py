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
from release_updates import ReleaseInfo, check_latest_release

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
        self.release_check_running = False
        self.latest_release: ReleaseInfo | None = None
        self._style()
        self._header()
        self._tabs()
        self._log()
        self._status()
        self.after(100, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(1000, lambda: self.check_program_updates(manual=False))

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
        ttk.Label(f, text="Passive Website-Sicherung und eigenständige Domain-/Hosting-/MX-Analyse.", style="Hint.TLabel").pack(anchor="w", pady=(3,0))

    def _tabs(self) -> None:
        self.tabs = ttk.Notebook(self); self.tabs.pack(fill="x", padx=14, pady=(0,8))
        self.t_capture = ttk.Frame(self.tabs, padding=12)
        self.t_domain = ttk.Frame(self.tabs, padding=12)
        self.t_origin = ttk.Frame(self.tabs, padding=12)
        self.t_update = ttk.Frame(self.tabs, padding=12)
        self.t_about = ttk.Frame(self.tabs, padding=12)
        for frame, title in [
            (self.t_capture,"Website-Sicherung"),(self.t_domain,"Domain-Analyse"),
            (self.t_origin,"Origin-IP ergänzen"),(self.t_update,"Updates"),(self.t_about,"Über"),
        ]:
            self.tabs.add(frame, text=title)
        self._capture_tab(); self._domain_tab(); self._origin_tab(); self._update_tab(); self._about_tab()

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
        ttk.Button(f,text="Ansicht aus Sicherung neu erzeugen",command=self.rebuild_mirror).grid(row=7,column=0,columnspan=2,sticky="w",pady=(10,0))

    def rebuild_mirror(self):
        if self.runner.running:
            return messagebox.showwarning("Vorgang läuft", "Es läuft bereits ein Vorgang.")
        source=filedialog.askdirectory(title="Ursprünglichen Sicherungsordner auswählen",initialdir=self.cap_out.get())
        if not source:return
        output=filedialog.askdirectory(title="Neuen oder leeren Ausgabeordner außerhalb der Sicherung auswählen",initialdir=str(Path(source).parent))
        if not output:return
        self.runner.start(["mirror","--source",source,"--output",output],"Lokale Ansicht aus vorhandener Sicherung erzeugen")

    def _domain_tab(self):
        f=self.t_domain
        self.dom_value=tk.StringVar(); self.dom_out=tk.StringVar(value=str(PUBLIC_ROOT/"Domainanalysen"))
        self._entry(f,0,"Domain / URL:",self.dom_value)
        self._entry(f,1,"Ausgabe-Elternordner:",self.dom_out,lambda:self._choose_dir(self.dom_out))
        ttk.Label(f,text="Analysiert DNS, Registrar/RDAP/WHOIS, Webserver/Hosting und besonders MX-/Mailserver-Infrastruktur inklusive Provider- und GeoIP-Hinweisen. Der PDF-Bericht wird automatisch im Ergebnisordner unter PDF-Berichte erzeugt.",wraplength=900,style="Hint.TLabel").grid(row=2,column=0,columnspan=3,sticky="w",pady=(3,8))
        ttk.Button(f,text="Domain analysieren",command=self.start_domain).grid(row=3,column=0,sticky="w")

    def _origin_tab(self):
        f=self.t_origin
        self.org_dir=tk.StringVar(); self.org_ips=tk.StringVar(); self.org_note=tk.StringVar()
        self._entry(f,0,"Domainanalyse- oder Sicherungsordner:",self.org_dir,lambda:self._choose_dir(self.org_dir))
        self._entry(f,1,"Bekannte Origin-/Server-IP(s):",self.org_ips)
        self._entry(f,2,"Quelle / Ermittlungsvermerk:",self.org_note)
        ttk.Label(f,text="Die IP wird nicht vom Programm als Origin ermittelt, sondern ausschließlich als manuell vorgegebener Befund gekennzeichnet und technisch angereichert. Der zugehörige PDF-Bericht wird danach automatisch aktualisiert.",wraplength=900,style="Hint.TLabel").grid(row=3,column=0,columnspan=3,sticky="w",pady=(4,8))
        ttk.Button(f,text="Origin-IP ergänzen",command=self.start_origin).grid(row=4,column=0,sticky="w")

    def _update_tab(self):
        f=self.t_update
        program = ttk.LabelFrame(f, text="Programmversion", padding=10, style="Section.TLabelframe")
        program.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0,12))
        ttk.Label(program,text=f"Installiert: {APP_VERSION}. Beim Start wird im Hintergrund nach einem neuen GitHub-Release gesucht.",wraplength=900).grid(row=0,column=0,columnspan=3,sticky="w")
        self.release_status = tk.StringVar(value="Noch nicht geprüft.")
        ttk.Label(program,textvariable=self.release_status,wraplength=900).grid(row=1,column=0,columnspan=3,sticky="w",pady=8)
        self.release_check_button = ttk.Button(program,text="Nach Updates suchen",command=self.check_program_updates)
        self.release_check_button.grid(row=2,column=0,sticky="w")
        self.release_download_button = ttk.Button(program,text="Update herunterladen",state="disabled",command=self.download_program_update)
        self.release_download_button.grid(row=2,column=1,sticky="w",padx=8)
        self.release_notes_button = ttk.Button(program,text="Release Notes anzeigen",state="disabled",command=self.show_release_notes)
        self.release_notes_button.grid(row=2,column=2,sticky="w")
        ttk.Label(program,text="Der Download öffnet das Quellcode-ZIP im Browser. ZIP vollständig entpacken, einschließlich .forensic_sitesaver, und die neue Version manuell starten.",wraplength=900,style="Hint.TLabel").grid(row=3,column=0,columnspan=3,sticky="w",pady=(8,0))
        ttk.Label(f,text="Python-Abhängigkeiten und Playwright-Browser",style="Section.TLabelframe.Label").grid(row=1,column=0,columnspan=3,sticky="w",pady=(0,8))
        ttk.Button(f,text="Auf Paketupdates prüfen",command=lambda:self.runner.start(["update","--check-only"],"Paketupdate-Prüfung")).grid(row=2,column=0,sticky="w")
        ttk.Button(f,text="Abhängigkeiten aktualisieren …",command=self.start_update).grid(row=2,column=1,sticky="w",padx=8)
        ttk.Button(f,text="Installierte Lizenzen neu erfassen",command=lambda:self.runner.start(["licenses"],"Lizenzinventar aktualisieren")).grid(row=2,column=2,sticky="w")

    def check_program_updates(self, manual=True):
        if self.release_check_running:
            return
        self.release_check_running = True
        self.latest_release = None
        self.release_check_button.config(state="disabled")
        self.release_download_button.config(state="disabled")
        self.release_notes_button.config(state="disabled")
        self.release_status.set("GitHub-Releases werden geprüft …")

        def worker():
            try:
                release = check_latest_release()
                self.events.put(("release_checked", (manual, release, None)))
            except Exception as exc:
                self.events.put(("release_checked", (manual, None, str(exc))))
        threading.Thread(target=worker, daemon=True).start()

    def _release_checked(self, manual, release, error):
        self.release_check_running = False
        self.release_check_button.config(state="normal")
        self.latest_release = release
        if error:
            self.release_status.set(f"Updateprüfung fehlgeschlagen: {error}")
            if manual:
                messagebox.showerror("Updateprüfung fehlgeschlagen",error,parent=self)
            return
        if release is None:
            text = "Auf GitHub ist noch kein freigegebenes Release verfügbar."
        elif not release.update_available:
            self.release_notes_button.config(state="normal")
            text = f"Du verwendest die aktuelle Version ({APP_VERSION}). GitHub-Release: {release.tag}."
        else:
            self.release_status.set(f"Update verfügbar: {release.tag}. Installiert: {APP_VERSION}.")
            self.release_download_button.config(state="normal")
            self.release_notes_button.config(state="normal")
            self._show_update_dialog(release)
            return
        self.release_status.set(text)
        if manual:
            messagebox.showinfo("Updateprüfung",text,parent=self)

    def _open_release_url(self, url):
        try:
            if not webbrowser.open(url):
                raise RuntimeError("Der Browser konnte nicht geöffnet werden.")
        except Exception as exc:
            messagebox.showerror("Öffnen fehlgeschlagen",f"{exc}\n\nAdresse: {url}",parent=self)

    def download_program_update(self):
        if self.latest_release and self.latest_release.update_available:
            self._open_release_url(self.latest_release.download_url)

    def show_release_notes(self):
        if self.latest_release:
            self._open_release_url(self.latest_release.release_url)

    def _show_update_dialog(self, release):
        dialog = tk.Toplevel(self)
        dialog.title("Update verfügbar")
        dialog.transient(self)
        dialog.geometry("620x420")
        dialog.minsize(500,320)
        frame = ttk.Frame(dialog,padding=14)
        frame.pack(fill="both",expand=True)
        ttk.Label(frame,text=f"Version {release.tag} ist verfügbar. Installiert ist {APP_VERSION}.",wraplength=570).pack(anchor="w")
        notes = ScrolledText(frame,wrap="word",height=10)
        notes.pack(fill="both",expand=True,pady=12)
        notes.insert("1.0",release.notes)
        notes.config(state="disabled")
        ttk.Label(frame,text="ZIP herunterladen, vollständig entpacken und die neue Version manuell starten.",wraplength=570).pack(anchor="w",pady=(0,10))
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(buttons,text="Release Notes anzeigen",command=lambda:self._open_release_url(release.release_url)).pack(side="left")
        ttk.Button(buttons,text="Update herunterladen",command=lambda:self._open_release_url(release.download_url)).pack(side="left",padx=8)
        later = ttk.Button(buttons,text="Später",command=dialog.destroy)
        later.pack(side="right")
        dialog.bind("<Escape>",lambda event:dialog.destroy())
        later.focus_set()

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
                elif kind=="release_checked":self._release_checked(*payload)
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
        self.runner.start(args,"Eigenständige Domain-/Hosting-/MX-Analyse")

    def start_origin(self):
        if not self.org_dir.get().strip() or not self.org_ips.get().strip():return messagebox.showerror("Fehlende Angaben","Domainanalyse-/Sicherungsordner und IP sind erforderlich.")
        self.runner.start(["origin","--domain-dir",self.org_dir.get(),"--ips",self.org_ips.get(),"--note",self.org_note.get()],"Origin-/Server-IP-Ergänzung")

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
