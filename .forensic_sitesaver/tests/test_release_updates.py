# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Release comparison, GitHub failures and background GUI update checks."""
from __future__ import annotations

import io
import json
import queue
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from common import APP_VERSION, REPOSITORY_URL
from release_updates import LATEST_RELEASE_API, ReleaseInfo, check_latest_release, is_newer_version


class VersionTests(unittest.TestCase):
    def test_semver_ordering(self):
        for candidate, installed, expected in [
            ("v1.10.0", "1.9.0", True),
            ("1.2.0", "1.10.0", False),
            ("2.0.0", "1.99.99", True),
            ("V1.1.1", "1.1.1", False),
            ("1.1.1+build.2", "1.1.1+build.1", False),
            ("1.1.1", "1.1.1-rc.1", True),
            ("1.1.1-rc.1", "1.1.1", False),
            ("1.1.1-rc.10", "1.1.1-rc.9", True),
            ("1.1.1-beta", "1.1.1-alpha", True),
            ("1.1.1-alpha", "1.1.1-2", True),
            ("1.1.1-alpha.1", "1.1.1-alpha", True),
        ]:
            with self.subTest(candidate=candidate, installed=installed):
                self.assertEqual(is_newer_version(candidate, installed), expected)

    def test_invalid_versions_are_rejected(self):
        for value in ["", "release-1.2.3", "1.2", "1.02.3", "1.2.3-01", "1.2.3-extra!", "1.2.3.4"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                is_newer_version(value, APP_VERSION)


class GitHubReleaseTests(unittest.TestCase):
    def check_response(self, data, installed=APP_VERSION):
        with patch("release_updates.urlopen",return_value=io.BytesIO(json.dumps(data).encode())) as fetch:
            result = check_latest_release(installed)
        request = fetch.call_args.args[0]
        self.assertEqual(request.full_url,LATEST_RELEASE_API)
        self.assertEqual(fetch.call_args.kwargs["timeout"],10)
        self.assertIn("application/vnd.github+json",request.headers.values())
        return result

    def test_new_release_and_source_download(self):
        release = self.check_response({"tag_name":"v1.2.0","body":"Neue Funktionen"}, installed="1.1.1")
        self.assertTrue(release.update_available)
        self.assertEqual(release.notes,"Neue Funktionen")
        self.assertEqual(release.release_url,REPOSITORY_URL + "/releases/tag/v1.2.0")
        self.assertEqual(release.download_url,REPOSITORY_URL + "/archive/refs/tags/v1.2.0.zip")

    def test_equal_or_older_release_is_not_an_update(self):
        for tag in [f"v{APP_VERSION}","v1.1.1","v1.0.0"]:
            with self.subTest(tag=tag):
                self.assertFalse(self.check_response({"tag_name":tag}).update_available)

    def test_drafts_and_prereleases_are_ignored(self):
        for data in [
            {"tag_name":"v2.0.0","draft":True},
            {"tag_name":"v2.0.0","prerelease":True},
            {"tag_name":"v2.0.0-rc.1"},
        ]:
            with self.subTest(data=data):
                self.assertIsNone(self.check_response(data))

    def test_missing_notes_have_a_fallback(self):
        self.assertEqual(self.check_response({"tag_name":"v1.2.0","body":None}).notes,"Keine Release Notes hinterlegt.")

    def test_remote_urls_cannot_replace_project_links(self):
        release = self.check_response({"tag_name":"v1.2.0","html_url":"file:///tmp/test","zipball_url":"https://example.test/"})
        self.assertTrue(release.release_url.startswith(REPOSITORY_URL + "/"))
        self.assertTrue(release.download_url.startswith(REPOSITORY_URL + "/"))

    def test_no_published_release(self):
        with patch("release_updates.urlopen",side_effect=HTTPError(LATEST_RELEASE_API,404,"Not Found",{},None)):
            self.assertIsNone(check_latest_release())

    def test_http_failures(self):
        for code, message in [(403,"begrenzt"),(429,"begrenzt"),(500,"HTTP 500")]:
            with self.subTest(code=code), patch("release_updates.urlopen",side_effect=HTTPError(LATEST_RELEASE_API,code,"error",{},None)):
                with self.assertRaisesRegex(RuntimeError,message):
                    check_latest_release()

    def test_offline_and_timeout(self):
        for error in [URLError("offline"),TimeoutError("timeout")]:
            with self.subTest(error=error), patch("release_updates.urlopen",side_effect=error):
                with self.assertRaisesRegex(RuntimeError,"nicht erreichbar"):
                    check_latest_release()

    def test_bad_release_data(self):
        for data in [[],{}, {"tag_name":123},{"tag_name":"invalid"},{"tag_name":"v1.2.0","body":["invalid"]}]:
            with self.subTest(data=data), self.assertRaises((RuntimeError,ValueError)):
                self.check_response(data)
        with patch("release_updates.urlopen",return_value=io.BytesIO(b"not json")):
            with self.assertRaisesRegex(RuntimeError,"keine gültigen Release-Daten"):
                check_latest_release()


try:
    from gui import App
except ImportError:
    App = None


@unittest.skipIf(App is None,"Tkinter ist nicht installiert")
class UpdateGuiTests(unittest.TestCase):
    def make_app(self):
        return SimpleNamespace(
            release_check_running=False,latest_release=None,events=queue.Queue(),
            release_check_button=Mock(),release_download_button=Mock(),release_notes_button=Mock(),
            release_status=Mock(),_show_update_dialog=Mock(),_open_release_url=Mock(),
        )

    def test_worker_only_queues_results_and_prevents_duplicate_checks(self):
        app = self.make_app()
        release = ReleaseInfo("v1.2.0","notes",True)
        with patch("gui.threading.Thread") as thread, patch("gui.check_latest_release",return_value=release):
            App.check_program_updates(app,manual=False)
            App.check_program_updates(app)
            thread.assert_called_once()
            self.assertTrue(thread.call_args.kwargs["daemon"])
            thread.call_args.kwargs["target"]()
        self.assertEqual(app.events.get_nowait(),("release_checked",(False,release,None)))
        app._show_update_dialog.assert_not_called()

    def test_background_failures_are_silent_and_manual_failures_are_visible(self):
        for manual in [False,True]:
            app = self.make_app()
            with patch("gui.messagebox.showerror") as error:
                App._release_checked(app,manual,None,"offline")
            self.assertEqual(error.call_count,int(manual))
            self.assertFalse(app.release_check_running)
            app.release_status.set.assert_called_once_with("Updateprüfung fehlgeschlagen: offline")

    def test_new_release_enables_download_and_shows_offer(self):
        app = self.make_app()
        release = ReleaseInfo("v1.2.0","notes",True)
        App._release_checked(app,False,release,None)
        app.release_download_button.config.assert_called_once_with(state="normal")
        app._show_update_dialog.assert_called_once_with(release)
        App.download_program_update(app)
        app._open_release_url.assert_called_once_with(release.download_url)

    def test_current_version_only_announces_manual_checks(self):
        for manual in [False,True]:
            app = self.make_app()
            with patch("gui.messagebox.showinfo") as info:
                App._release_checked(app,manual,ReleaseInfo(f"v{APP_VERSION}","notes",False),None)
            self.assertEqual(info.call_count,int(manual))
            app.release_download_button.config.assert_not_called()
            app._show_update_dialog.assert_not_called()

    def test_missing_release_only_announces_manual_checks(self):
        for manual in [False,True]:
            app = self.make_app()
            with patch("gui.messagebox.showinfo") as info:
                App._release_checked(app,manual,None,None)
            self.assertEqual(info.call_count,int(manual))
            app.release_download_button.config.assert_not_called()
            app._show_update_dialog.assert_not_called()

    def test_worker_queues_network_errors(self):
        app = self.make_app()
        with patch("gui.threading.Thread") as thread, patch("gui.check_latest_release",side_effect=RuntimeError("offline")):
            App.check_program_updates(app)
            thread.call_args.kwargs["target"]()
        self.assertEqual(app.events.get_nowait(),("release_checked",(True,None,"offline")))


if __name__ == "__main__":
    unittest.main()
