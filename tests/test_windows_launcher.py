"""Exercise the real CMD/Windows PowerShell 5.1 chain without network downloads."""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Windows PowerShell required")
class WindowsLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="proxy-audit-launcher-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.fake_python = Path(cls.build.name) / "python.exe"
        # A real native process is necessary to reproduce PS 5.1 stderr handling.
        source = r'''
using System;
using System.IO;
using System.Reflection;
class FakePython {
    static int Main(string[] args) {
        string mode = Environment.GetEnvironmentVariable("PROXY_AUDIT_TEST_MODE");
        string command = String.Join(" ", args);
        if (command.Contains("sys.version_info")) {
            Console.WriteLine(mode == "old" ? "3.9.0" : "3.12.0");
            return mode == "old" ? 1 : 0;
        }
        if (command.Contains("-m venv")) {
            if (mode == "venv-fail") {
                Console.Error.WriteLine("SYNTHETIC_VENV_FAILURE");
                return 3;
            }
            string target = Path.Combine(args[args.Length - 1], "Scripts", "python.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            File.Copy(Assembly.GetExecutingAssembly().Location, target, true);
            return 0;
        }
        if (command.Contains("import flask")) {
            if (mode.StartsWith("deps") && !File.Exists("installed.marker")) {
                Console.Error.WriteLine("ModuleNotFoundError: synthetic missing flask");
                return 1;
            }
            return 0;
        }
        if (command.Contains("-m pip")) {
            Console.WriteLine("SYNTHETIC_PIP_REACHED");
            if (mode == "deps-fail") {
                Console.Error.WriteLine("SYNTHETIC_PIP_NETWORK_FAILURE");
                return 2;
            }
            File.WriteAllText("installed.marker", "installed");
            return 0;
        }
        Console.WriteLine("SYNTHETIC_WEB_ARGS " + command);
        Console.Error.WriteLine("SYNTHETIC_WEB_STDERR");
        return mode == "web-fail" ? 23 : 0;
    }
}
'''
        build_script = Path(cls.build.name) / "build.ps1"
        build_script.write_text(
            "$ErrorActionPreference = 'Stop'\nAdd-Type -TypeDefinition @'\n"
            + source
            + "\n'@ -OutputAssembly (Join-Path $PSScriptRoot 'python.exe') "
            "-OutputType ConsoleApplication\n",
            encoding="ascii",
        )
        subprocess.run(
            [POWERSHELL, "-NoProfile", "-File", str(build_script)],
            check=True, capture_output=True, timeout=30,
        )

    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix="proxy-audit-launcher-")
        self.addCleanup(self.sandbox.cleanup)
        # Exercise Unicode, spaces, apostrophes, parentheses, and exclamation marks.
        self.project = Path(self.sandbox.name) / "\u4e2d\u6587 user's project (test)!"
        (self.project / "scripts").mkdir(parents=True)
        for name in ("start-web.cmd", "start-web.ps1", "scripts/start_web_runtime.ps1"):
            shutil.copy2(ROOT / name, self.project / name)
        (self.project / "requirements.txt").write_text("", encoding="ascii")
        (self.project / "scripts/web_app.py").write_text("", encoding="ascii")
        self.environment = os.environ.copy()
        for key in ("PROXY_AUDIT_LAUNCHER_LOG", "PROXY_AUDIT_NO_PAUSE"):
            self.environment.pop(key, None)
        self.environment.update({
            "PROXY_AUDIT_NO_PAUSE": "1",
            "PROXY_AUDIT_TEST_MODE": "ok",
            "PATH": os.path.join(os.environ["SystemRoot"], "System32"),
            "TEMP": self.sandbox.name,
            "TMP": self.sandbox.name,
        })
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]

    def install_fake_python(self, *, base=False):
        destination = self.project / ("python.exe" if base else ".venv/Scripts/python.exe")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.fake_python, destination)
        if base:
            self.environment["PATH"] = str(self.project) + os.pathsep + self.environment["PATH"]

    def command(self, *, direct=False, port=None, skip_core=True, driver=None):
        args = ["-NoOpen", "-Port", str(self.port if port is None else port)]
        if skip_core:
            args.append("-SkipCoreDownload")
        if direct:
            return [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(driver or self.project / "start-web.ps1"), *args]
        return [os.environ["ComSpec"], "/d", "/c", "start-web.cmd", *args]

    def run_launcher(self, **options):
        result = subprocess.run(
            self.command(**options), cwd=self.project, env=self.environment,
            capture_output=True, timeout=30,
        )
        self.output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        logs = list((self.project / "logs").glob("*.log"))
        logs += list(Path(self.sandbox.name).glob("proxy-audit-*.log"))
        self.assertEqual(len(logs), 1, self.output)
        self.log = logs[0].read_text(encoding="utf-8-sig", errors="replace")
        self.assertIn("Launcher exit", self.log)
        return result.returncode

    def test_missing_python_is_logged_with_install_instructions(self):
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("A working Python 3.10+ was not found", self.log)
        self.assertIn("Add python.exe to PATH", self.output)

    def test_old_python_is_rejected(self):
        self.install_fake_python(base=True)
        self.environment["PROXY_AUDIT_TEST_MODE"] = "old"
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("3.9.0", self.log)
        self.assertIn("A working Python 3.10+ was not found", self.log)

    def test_broken_venv_is_not_reported_as_success(self):
        self.install_fake_python()
        self.environment["PROXY_AUDIT_TEST_MODE"] = "old"
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("rename .venv to .venv-backup", self.log)

    def test_native_stderr_does_not_skip_first_dependency_install(self):
        self.install_fake_python(base=True)
        self.environment["PROXY_AUDIT_TEST_MODE"] = "deps-ok"
        self.assertEqual(self.run_launcher(), 0, self.output)
        self.assertIn("Creating an isolated Python environment", self.log)
        self.assertIn("ModuleNotFoundError", self.log)
        self.assertIn("SYNTHETIC_PIP_REACHED", self.log)
        self.assertIn("SYNTHETIC_WEB_ARGS", self.log)

    def test_dependency_failure_keeps_native_error_and_returns_failure(self):
        self.install_fake_python()
        self.environment["PROXY_AUDIT_TEST_MODE"] = "deps-fail"
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("SYNTHETIC_PIP_NETWORK_FAILURE", self.log)
        self.assertIn("Failed to install Python dependencies", self.output)
        self.assertNotIn("SYNTHETIC_WEB_ARGS", self.log)

    def test_venv_failure_keeps_native_error(self):
        self.install_fake_python(base=True)
        self.environment["PROXY_AUDIT_TEST_MODE"] = "venv-fail"
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("SYNTHETIC_VENV_FAILURE", self.log)
        self.assertIn("Failed to create .venv", self.log)

    def test_web_crash_is_logged_and_returns_failure(self):
        self.install_fake_python()
        self.environment["PROXY_AUDIT_TEST_MODE"] = "web-fail"
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("SYNTHETIC_WEB_STDERR", self.log)
        self.assertIn("Web server exited with code 23", self.log)

    def test_download_failure_is_logged_without_network_access(self):
        self.install_fake_python()
        driver = self.project / "download-test.ps1"
        driver.write_text(
            "param([switch]$NoOpen, [int]$Port)\n"
            "function Invoke-WebRequest { throw 'SYNTHETIC_DOWNLOAD_FAILURE' }\n"
            "& (Join-Path $PSScriptRoot 'start-web.ps1') -NoOpen:$NoOpen -Port $Port\n"
            "exit $LASTEXITCODE\n", encoding="ascii",
        )
        self.assertNotEqual(self.run_launcher(direct=True, driver=driver, skip_core=False), 0)
        self.assertIn("SYNTHETIC_DOWNLOAD_FAILURE", self.log)
        self.assertIn("Failed to download sing-box from GitHub", self.log)

    def test_success_forwards_arguments_without_pausing(self):
        self.install_fake_python()
        self.environment.pop("PROXY_AUDIT_NO_PAUSE")
        self.assertEqual(self.run_launcher(), 0, self.output)
        self.assertIn(f"--port {self.port} --no-open", self.log)
        self.assertIn("SYNTHETIC_WEB_STDERR", self.log)
        self.assertNotIn("Press any key", self.output)
        self.assertIn(self.project.name, self.log)

    def test_port_in_use_fails_before_installing(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            self.assertNotEqual(self.run_launcher(port=listener.getsockname()[1]), 0)
        self.assertIn("The port may be in use or reserved", self.log)
        self.assertNotIn("Creating an isolated", self.log)

    def test_invalid_port_is_logged(self):
        self.assertNotEqual(self.run_launcher(port=0), 0)
        self.assertIn("Port", self.log)
        self.assertIn("FAILED:", self.log)

    def test_incomplete_zip_is_logged(self):
        (self.project / "requirements.txt").unlink()
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("Extract the entire ZIP", self.log)

    def test_inner_parse_error_is_logged(self):
        (self.project / "scripts/start_web_runtime.ps1").write_text("if (", encoding="ascii")
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("FAILED:", self.log)
        self.assertNotIn("Creating an isolated", self.log)

    def test_unwritable_log_directory_falls_back_to_temp(self):
        (self.project / "logs").write_text("blocks directory creation", encoding="ascii")
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("A working Python 3.10+ was not found", self.log)
        self.assertTrue(list(Path(self.sandbox.name).glob("proxy-audit-startup-*.log")))

    def test_direct_powershell_also_falls_back_and_returns_failure(self):
        (self.project / "logs").write_text("blocks directory creation", encoding="ascii")
        self.assertNotEqual(self.run_launcher(direct=True), 0)
        self.assertIn("A working Python 3.10+ was not found", self.log)

    def test_missing_powershell_has_a_bootstrap_log(self):
        self.environment["SystemRoot"] = str(self.project / "absent-windows")
        self.assertNotEqual(self.run_launcher(), 0)
        self.assertIn("Windows PowerShell was not found", self.log)

    def test_failure_waits_for_key_then_preserves_exit_code(self):
        self.environment.pop("PROXY_AUDIT_NO_PAUSE")
        output_path = Path(self.sandbox.name) / "console.txt"
        with output_path.open("wb") as output:
            process = subprocess.Popen(
                self.command(), cwd=self.project, env=self.environment,
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if b"Press any key to close" in output_path.read_bytes():
                        break
                    self.assertIsNone(process.poll(), output_path.read_bytes())
                    time.sleep(0.1)
                self.assertIn(b"Press any key to close", output_path.read_bytes())
                self.assertIsNone(process.poll(), "Failure window closed before a key press")
                process.communicate(input=b"x\r\n", timeout=10)
                self.assertNotEqual(process.returncode, 0)
            finally:
                if process.poll() is None:
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                    process.wait(timeout=10)
                process.stdin.close()


if __name__ == "__main__":
    unittest.main()
