"""Minimal The Day Before status switch for Discord on Windows."""

from __future__ import annotations

import ctypes
import json
import os
import queue
import struct
import sys
import threading
import time
import uuid
import tkinter as tk
from ctypes import wintypes
from pathlib import Path
from tkinter import messagebox, simpledialog

APP_TITLE = "Nightfall"
GAME_NAME = "The Day Before"
APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
GAMES_FILE = DATA_DIR / "games.json"
RPC_LOG = DATA_DIR / "discord-rpc.log"
CLIENT_ID_FILE = DATA_DIR / "discord-client-id.dat"


def log_rpc(message: str):
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with RPC_LOG.open("a", encoding="utf-8") as log:
            log.write(message + "\n")
    except OSError:
        pass


def read_data() -> dict:
    try:
        data = json.loads(GAMES_FILE.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, json.JSONDecodeError):
        data = {}
    old_games = data.get("games", [])
    old_game = next((g for g in old_games if g.get("name", "").casefold() == GAME_NAME.casefold()), None)
    if old_game is None and old_games:
        old_game = old_games[0]
    game = {
        "name": old_game.get("name", GAME_NAME) if old_game else GAME_NAME,
        "cover": old_game.get("cover", "") if old_game else "",
        "asset": old_game.get("asset", "") if old_game else "",
        "description": old_game.get("description", "") if old_game else "",
    }
    data["games"] = [game]
    return data


def save_data(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cleaned = {key: value for key, value in data.items() if key != "client_id"}
    GAMES_FILE.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding="utf-8")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Encrypt/decrypt a small config value with Windows DPAPI for this user account."""
    if os.name != "nt":
        raise RuntimeError("Защита ID приложения доступна только в Windows.")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    input_buffer = ctypes.create_string_buffer(data)
    input_blob = _DataBlob(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
    output_blob = _DataBlob()
    description = wintypes.LPWSTR()
    if protect:
        function = crypt.CryptProtectData
        function.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(_DataBlob)]
        function.restype = wintypes.BOOL
        succeeded = function(ctypes.byref(input_blob), "The Day Before Discord ID", None,
                             None, None, 1, ctypes.byref(output_blob))
    else:
        function = crypt.CryptUnprotectData
        function.argtypes = [ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                             wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        function.restype = wintypes.BOOL
        succeeded = function(ctypes.byref(input_blob), ctypes.byref(description), None,
                             None, None, 1, ctypes.byref(output_blob))
    if not succeeded:
        code = ctypes.get_last_error()
        raise RuntimeError(f"Не удалось защитить настройки Windows (ошибка {code}).")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(output_blob.pbData)
        if description:
            kernel.LocalFree(description)


def save_client_id(client_id: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    encrypted = _dpapi(client_id.encode("utf-8"), protect=True)
    temp_file = CLIENT_ID_FILE.with_suffix(".tmp")
    temp_file.write_bytes(encrypted)
    temp_file.replace(CLIENT_ID_FILE)


def load_client_id() -> str:
    try:
        encrypted = CLIENT_ID_FILE.read_bytes()
    except FileNotFoundError:
        return ""
    return _dpapi(encrypted, protect=False).decode("utf-8")


class DiscordRPC:
    """Persistent Discord IPC connection with a reader for RPC replies and pings."""

    def __init__(self, client_id: str, handshake_timeout: float = 8):
        self.pipe = None
        self.responses = queue.Queue()
        self.reader_error = None
        self.reader = None
        self.write_lock = threading.Lock()
        if os.name != "nt":
            raise RuntimeError("Подключение к Discord RPC поддерживается в Windows.")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.create_file = kernel32.CreateFileW
        self.create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.create_file.restype = wintypes.HANDLE
        self.write_file = kernel32.WriteFile
        self.write_file.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        self.write_file.restype = wintypes.BOOL
        self.read_file = kernel32.ReadFile
        self.read_file.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                   ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        self.read_file.restype = wintypes.BOOL
        self.cancel_io = kernel32.CancelIoEx
        self.cancel_io.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        self.cancel_io.restype = wintypes.BOOL
        self.close_handle = kernel32.CloseHandle

        last_error = None
        attempt_timeout = min(handshake_timeout, 1.5)
        for number in range(10):
            handle = self.create_file(rf"\\?\pipe\discord-ipc-{number}", 0xC0000000, 0,
                                      None, 3, 0, None)
            if handle == wintypes.HANDLE(-1).value:
                continue
            self.pipe = handle
            try:
                log_rpc(f"Trying discord-ipc-{number}.")
                self._send_frame_bounded(0, {"v": 1, "client_id": client_id}, attempt_timeout)
                log_rpc(f"Handshake sent on discord-ipc-{number}.")
                result = queue.Queue(maxsize=1)

                def read_handshake(pipe_handle=handle):
                    try:
                        result.put((True, self._read_frame(pipe_handle)))
                    except Exception as error:
                        result.put((False, error))

                threading.Thread(target=read_handshake, daemon=True).start()
                try:
                    succeeded, frame = result.get(timeout=attempt_timeout)
                except queue.Empty:
                    raise RuntimeError(f"Discord не ответил на handshake канала {number}.")
                if not succeeded:
                    raise frame
                opcode, ready = frame
                log_rpc(f"Handshake response on pipe {number}: opcode={opcode}, event={ready.get('evt')}")
                if opcode == 2:
                    raise RuntimeError(ready.get("message", "Discord отклонил подключение."))
                if opcode != 1 or ready.get("evt") != "READY":
                    raise RuntimeError(f"Неожиданный ответ Discord при подключении (opcode {opcode}).")
                log_rpc(f"Discord handshake complete on discord-ipc-{number}.")
                return
            except Exception as error:
                last_error = error
                log_rpc(f"Handshake failed on discord-ipc-{number}: {error}")
                self.close()

        if last_error:
            raise RuntimeError(f"Не удалось подключиться к Discord: {last_error}") from last_error
        error_code = ctypes.get_last_error()
        log_rpc(f"Could not open a Discord IPC pipe; Win32 error {error_code}.")
        raise RuntimeError(f"Не удалось подключиться к Discord (ошибка Windows {error_code}).")

    def _send_frame(self, opcode: int, payload: dict):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        packet = struct.pack("<II", opcode, len(raw)) + raw
        written = wintypes.DWORD()
        with self.write_lock:
            if not self.write_file(self.pipe, packet, len(packet), ctypes.byref(written), None):
                code = ctypes.get_last_error()
                log_rpc(f"Write failed (opcode={opcode}, Win32 error={code}).")
                raise RuntimeError(f"Ошибка записи в Discord IPC (код {code}).")
            if written.value != len(packet):
                raise RuntimeError("Discord IPC принял только часть запроса.")

    def _send_frame_bounded(self, opcode: int, payload: dict, timeout: float):
        result = queue.Queue(maxsize=1)

        def write_frame():
            try:
                self._send_frame(opcode, payload)
                result.put((True, None))
            except Exception as error:
                result.put((False, error))

        threading.Thread(target=write_frame, daemon=True).start()
        try:
            succeeded, error = result.get(timeout=timeout)
        except queue.Empty:
            log_rpc(f"IPC write timed out (opcode={opcode}, timeout={timeout:g}s).")
            raise RuntimeError(f"Discord не принял IPC-запрос за {timeout:g} сек.")
        if not succeeded:
            raise error

    def _read_frame(self, pipe=None):
        pipe = self.pipe if pipe is None else pipe
        header = ctypes.create_string_buffer(8)
        count = wintypes.DWORD()
        if not self.read_file(pipe, header, 8, ctypes.byref(count), None) or count.value != 8:
            raise RuntimeError(f"Discord закрыл IPC-соединение (код {ctypes.get_last_error()}).")
        opcode, length = struct.unpack("<II", header.raw)
        if length > 1024 * 1024:
            raise RuntimeError("Discord прислал некорректный ответ.")
        body = ctypes.create_string_buffer(length)
        if length and (not self.read_file(pipe, body, length, ctypes.byref(count), None)
                       or count.value != length):
            raise RuntimeError(f"Не удалось прочитать ответ Discord (код {ctypes.get_last_error()}).")
        return opcode, json.loads(body.raw.decode("utf-8")) if length else {}

    def set_activity(self, activity: dict | None, response_timeout: float = 10):
        nonce = str(uuid.uuid4())
        payload = {"cmd": "SET_ACTIVITY", "args": {"pid": os.getpid(), "activity": activity},
                   "nonce": nonce}
        self._send_frame_bounded(1, payload, min(3, response_timeout))
        log_rpc("SET_ACTIVITY sent." if activity else "Clear activity sent.")
        if self.reader is None:
            # Start background reads only after the first request is already on the pipe.
            self.reader = threading.Thread(target=self._read_loop, daemon=True)
            self.reader.start()
        for _ in range(max(1, int(response_timeout * 10))):
            if self.reader_error:
                raise RuntimeError(f"Соединение с Discord прервано: {self.reader_error}")
            try:
                response = self.responses.get(timeout=0.1)
            except queue.Empty:
                continue
            if response.get("nonce") != nonce:
                log_rpc("Unmatched RPC frame received.")
                continue
            if response.get("evt") == "ERROR":
                data = response.get("data", {})
                log_rpc(f"Discord returned an RPC error: {data}")
                raise RuntimeError(data.get("message", f"Discord RPC ошибка {data.get('code', '')}"))
            log_rpc("SET_ACTIVITY acknowledged by Discord.")
            return
        raise RuntimeError(f"Discord не подтвердил обновление статуса за {response_timeout:g} сек.")

    def _read_loop(self):
        try:
            while self.pipe is not None:
                opcode, payload = self._read_frame()
                if opcode == 3:
                    self._send_frame(4, payload)
                elif opcode == 2:
                    raise RuntimeError(payload.get("message", "Discord закрыл IPC-соединение."))
                else:
                    self.responses.put(payload)
        except Exception as error:
            if self.pipe is not None:
                self.reader_error = error
                log_rpc(f"RPC reader stopped: {error}")

    def close(self):
        pipe, self.pipe = self.pipe, None
        if pipe is not None:
            # The reader thread may be blocked in synchronous ReadFile. Cancel it
            # before closing the named-pipe handle so shutdown cannot hang.
            self.cancel_io(pipe, None)
            self.close_handle(pipe)
            log_rpc("Discord IPC connection closed.")


class GameShelf(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("360x500")
        self.resizable(False, False)
        self.data = read_data()
        self.game = self.data["games"][0]
        legacy_client_id = str(self.data.pop("client_id", "")).strip()
        try:
            self.client_id = load_client_id() or legacy_client_id
        except Exception as error:
            messagebox.showerror(APP_TITLE, f"Не удалось прочитать зашифрованный ID: {error}\nВведите ID заново.")
            self.client_id = ""
        if self.client_id and not CLIENT_ID_FILE.exists():
            save_client_id(self.client_id)
        self.discord_rpc = None
        self.discord_rpc_client_id = None
        self.rpc_busy = False
        self.rpc_results = queue.Queue()
        self.closing = False
        self.active = False
        self.reenable_after = 0.0
        self.reenable_timer = None
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_ui()
        save_data(self.data)
        self.after(100, self._poll_rpc_result)

    def _build_ui(self):
        self.geometry("360x500")
        self.configure(bg="#080a0f")
        self.canvas = tk.Canvas(self, width=360, height=500, bd=0, highlightthickness=0, bg="#080a0f")
        self.canvas.pack(fill="both", expand=True)
        self._draw_background()

        self.canvas.create_text(180, 23, text="NIGHTFALL  /  DISCORD", fill="#8f9aa8",
                                font=("Segoe UI", 8, "bold"), anchor="center")
        self.canvas.create_rectangle(20, 38, 340, 39, fill="#303843", outline="")

        self.canvas.create_rectangle(130, 72, 230, 172, fill="#10151d", outline="#46515d",
                                     width=1, tags=("edit",))
        for y, knob_x in ((103, 166), (122, 191), (141, 174)):
            self.canvas.create_line(154, y, 206, y, fill="#6f7b88", width=2, tags=("edit",))
            self.canvas.create_oval(knob_x - 5, y - 5, knob_x + 5, y + 5,
                                    fill="#d8dde5", outline="#d8dde5", tags=("edit",))
        self.canvas.create_text(180, 190, text="НАСТРОИТЬ ИГРУ", fill="#d8dde5",
                                font=("Segoe UI", 8, "bold"), anchor="center", tags=("edit",))
        self.canvas.tag_bind("edit", "<Button-1>", self._open_game_editor)
        self.canvas.tag_bind("edit", "<Enter>", lambda _event: self.canvas.configure(cursor="hand2"))
        self.canvas.tag_bind("edit", "<Leave>", lambda _event: self.canvas.configure(cursor=""))

        self.name_label_id = self.canvas.create_text(180, 263, text=self.game.get("name", GAME_NAME),
                                                     fill="#f1f3f6", font=("Segoe UI", 12, "bold"),
                                                     anchor="center", width=320)
        self.description_label_id = self.canvas.create_text(
            180, 302, text=self.game.get("description", "").strip() or "Описание не задано",
            fill="#a4acb8", font=("Segoe UI", 9), anchor="center", width=310)
        self.status_label = self.canvas.create_text(180, 365, text="СТАТУС ВЫКЛЮЧЕН",
                                                    fill="#8994a1", font=("Segoe UI", 8, "bold"), anchor="center")
        self.status_button = tk.Button(
            self, text="Показать в Discord", command=self._toggle_status,
            font=("Segoe UI", 9, "bold"), bg="#d8dde5", fg="#10141a",
            activebackground="#f1f3f6", activeforeground="#10141a",
            disabledforeground="#707987", relief="flat", bd=0, cursor="hand2")
        self.canvas.create_window(180, 414, window=self.status_button, width=260, height=40)

    def _draw_background(self):
        # A lightweight code-drawn night scene keeps the app self-contained.
        bands = ["#101720", "#0f151d", "#0d131a", "#0b1118", "#090e14",
                 "#080d13", "#080c12", "#080b10", "#080a0f", "#080a0f"]
        for index, color in enumerate(bands):
            y0 = index * 50
            self.canvas.create_rectangle(0, y0, 360, y0 + 51, fill=color, outline="")
        self.canvas.create_oval(248, 70, 318, 140, fill="#151e28", outline="")
        self.canvas.create_oval(263, 77, 328, 142, fill="#101720", outline="")
        self.canvas.create_polygon(0, 292, 32, 270, 66, 290, 98, 260, 130, 291,
                                   164, 270, 196, 290, 232, 264, 268, 292, 312, 270,
                                   360, 292, 360, 500, 0, 500,
                                   fill="#0a1016", outline="")
        buildings = [
            (0, 338, 28, 434), (33, 318, 65, 438), (70, 348, 104, 440),
            (109, 310, 146, 435), (151, 337, 187, 440), (192, 323, 226, 437),
            (231, 309, 269, 439), (274, 345, 304, 440), (309, 320, 346, 435),
            (350, 352, 360, 435),
        ]
        for x0, y0, x1, y1 in buildings:
            self.canvas.create_rectangle(x0, y0, x1, y1, fill="#0b1117", outline="#121a22")
            for wx in range(x0 + 10, x1 - 4, 16):
                for wy in range(y0 + 12, y1 - 8, 20):
                    if (wx * 7 + wy * 3) % 5 == 0:
                        self.canvas.create_rectangle(wx, wy, wx + 3, wy + 5,
                                                     fill="#34332e", outline="")
        self.canvas.create_rectangle(0, 440, 360, 500, fill="#0a1016", outline="")
        self.canvas.create_polygon(135, 440, 225, 440, 332, 500, 28, 500,
                                   fill="#0c1218", outline="")
        self.canvas.create_line(0, 440, 360, 440, fill="#1a222b", width=1)
        self.canvas.create_line(180, 444, 180, 449, fill="#343a3d", width=2)
        self.canvas.create_line(180, 456, 180, 464, fill="#292f33", width=3)
        self.canvas.create_line(180, 475, 180, 490, fill="#20272c", width=4)
        self.canvas.create_line(82, 500, 152, 440, fill="#111a21", width=1)
        self.canvas.create_line(278, 500, 208, 440, fill="#111a21", width=1)

    def _refresh_game_labels(self):
        self.canvas.itemconfigure(self.name_label_id, text=self.game.get("name", GAME_NAME))
        description = self.game.get("description", "").strip() or "Описание не задано"
        self.canvas.itemconfigure(self.description_label_id, text=description)

    def _edit_client_id(self):
        value = simpledialog.askstring("Discord", "Application ID из Discord Developer Portal:",
                                       initialvalue=self.client_id, parent=self)
        if value is None:
            return False
        value = value.strip()
        if not value.isdecimal():
            messagebox.showerror(APP_TITLE, "Нужен числовой Application ID из Discord Developer Portal.")
            return False
        try:
            save_client_id(value)
            self.client_id = value
            return True
        except Exception as error:
            messagebox.showerror(APP_TITLE, f"Не удалось зашифровать ID приложения: {error}")
            return False

    @staticmethod
    def _connect_discord_rpc(client_id: str, timeout: float = 10):
        """Wait briefly for Discord to become ready, then establish IPC."""
        last_error = None
        deadline = time.monotonic() + timeout
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            try:
                remaining = max(0.5, deadline - time.monotonic())
                return DiscordRPC(client_id, handshake_timeout=min(remaining, 4))
            except Exception as error:
                last_error = error
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    log_rpc(f"Discord handshake retry {attempt}; waiting before retry: {error}")
                    time.sleep(min(1.0, remaining))
        raise RuntimeError(f"Не удалось подключиться к Discord за {timeout:.0f} секунд: {last_error}") from last_error

    @staticmethod
    def _valid_setting(candidate: str):
        return len(candidate) <= 128

    @staticmethod
    def _valid_asset_setting(candidate: str):
        return len(candidate) <= 300

    def _open_game_editor(self, _event=None):
        if self.rpc_busy:
            return
        editor = tk.Toplevel(self)
        editor.title("Настройка игры")
        editor.geometry("430x480")
        editor.resizable(False, False)
        editor.configure(bg="#11131a")
        editor.transient(self)
        editor.grab_set()

        tk.Label(editor, text="Настройки игры", bg="#11131a", fg="#f3f4f7",
                 font=("Segoe UI", 18, "bold")).pack(fill="x", padx=26, pady=(22, 18))
        form = tk.Frame(editor, bg="#11131a")
        form.pack(fill="x", padx=26)

        def add_field(label: str, value: str):
            tk.Label(form, text=label, bg="#11131a", fg="#c6cad4",
                     font=("Segoe UI", 9, "bold")).pack(fill="x", pady=(0, 6))
            var = tk.StringVar(value=value)
            entry = tk.Entry(form, textvariable=var, font=("Segoe UI", 10),
                             bg="#20232c", fg="#f2f3f7", insertbackground="#f2f3f7",
                             justify="center", relief="flat", bd=0, highlightthickness=1,
                             highlightbackground="#343947", highlightcolor="#6874ff")
            entry.configure(validate="key", validatecommand=(self.register(self._valid_setting), "%P"))
            entry.pack(fill="x", ipady=9, pady=(0, 18))
            return var, entry

        name_var, name_entry = add_field("НАЗВАНИЕ ИГРЫ", self.game.get("name", GAME_NAME))
        description_var, _description_entry = add_field("ОПИСАНИЕ В DISCORD", self.game.get("description", ""))
        tk.Label(form, text="До 128 символов", bg="#11131a", fg="#8f95a5",
                 font=("Segoe UI", 8)).pack(fill="x", pady=(0, 15))
        asset_var, asset_entry = add_field("КЛЮЧ ИЛИ ПУБЛИЧНАЯ ССЫЛКА НА ОБЛОЖКУ", self.game.get("asset", ""))
        asset_entry.configure(validatecommand=(self.register(self._valid_asset_setting), "%P"))

        tk.Label(editor, text="Введите ключ Art Asset или прямую публичную HTTPS-ссылку. Локальные файлы программа не загружает.",
                 bg="#11131a", fg="#8f95a5", font=("Segoe UI", 8),
                 wraplength=378, justify="center").pack(fill="x", padx=26, pady=(12, 6))

        actions = tk.Frame(editor, bg="#11131a")
        actions.pack(fill="x", padx=26, pady=(4, 20))
        button_row = tk.Frame(actions, bg="#11131a")
        button_row.pack(anchor="center")

        def save_and_close():
            name = name_var.get().strip()
            if not name:
                messagebox.showerror("Настройка игры", "Введите название игры.", parent=editor)
                return
            self.game["name"] = name
            self.game["description"] = description_var.get().strip()
            self.game["asset"] = asset_var.get().strip()
            save_data(self.data)
            self._refresh_game_labels()
            editor.destroy()
            if self.active:
                self._run_rpc(self._make_activity())

        tk.Button(button_row, text="Отмена", command=editor.destroy,
                  font=("Segoe UI", 10), bg="#242731", fg="#d7dae2",
                  activebackground="#30343e", activeforeground="white", relief="flat",
                  bd=0, cursor="hand2").pack(side="left", padx=(0, 9), ipadx=14, ipady=8)
        tk.Button(button_row, text="Сохранить", command=save_and_close,
                  font=("Segoe UI", 10, "bold"), bg="#5865f2", fg="white",
                  activebackground="#6b76ff", activeforeground="white", relief="flat",
                  bd=0, cursor="hand2").pack(side="left", ipadx=18, ipady=8)
        name_entry.focus_set()

    def _make_activity(self):
        name = self.game.get("name", GAME_NAME).strip() or GAME_NAME
        activity = {"name": name, "type": 0, "instance": False}
        description = self.game.get("description", "").strip()
        if description:
            activity["details"] = description
        if self.game.get("asset"):
            activity["assets"] = {"large_image": self.game["asset"]}
        return activity

    def _toggle_status(self):
        if self.rpc_busy:
            return
        if self.active:
            self._run_rpc(None)
            return
        if time.monotonic() < self.reenable_after:
            self._update_reenable_countdown()
            return
        if not self.client_id:
            if not self._edit_client_id():
                return
        self._run_rpc(self._make_activity())

    def _run_rpc(self, activity: dict | None):
        self.rpc_busy = True
        self.status_button.configure(state="disabled")
        if activity is None:
            self.canvas.itemconfigure(self.status_label, text="ОТКЛЮЧАЮ…")
            self.status_button.configure(text="Отключаю…")
        else:
            self.canvas.itemconfigure(self.status_label, text="ПОДКЛЮЧАЮСЬ…")
        threading.Thread(target=self._rpc_worker,
                         args=(self.client_id, activity), daemon=True).start()

    def _rpc_worker(self, client_id: str, activity: dict | None):
        error = None
        try:
            log_rpc("Status worker started.")
            if activity is None:
                rpc = self.discord_rpc
                if rpc is not None and self.discord_rpc_client_id == client_id:
                    try:
                        log_rpc("Clear worker: sending null activity over the existing IPC connection.")
                        rpc.set_activity(None, response_timeout=3)
                    except Exception as old_error:
                        log_rpc(f"Existing IPC clear failed; reconnecting: {old_error}")
                        self.discord_rpc = None
                        self.discord_rpc_client_id = None
                        threading.Thread(target=rpc.close, daemon=True).start()
                        rpc = None
                if rpc is None:
                    rpc = self._connect_discord_rpc(client_id)
                    rpc.set_activity(None, response_timeout=3)
                    self.discord_rpc = rpc
                    self.discord_rpc_client_id = client_id
                log_rpc("Clear worker: Discord acknowledged null activity.")
                self.rpc_results.put((None, False))
                return
            if self.discord_rpc is None or self.discord_rpc_client_id != client_id:
                if self.discord_rpc is not None:
                    self.discord_rpc.close()
                self.discord_rpc = self._connect_discord_rpc(client_id)
                self.discord_rpc_client_id = client_id
            log_rpc("Status worker: RPC object ready.")
            self.discord_rpc.set_activity(activity)
        except Exception as exc:
            error = str(exc)
            if self.discord_rpc is not None:
                rpc = self.discord_rpc
                self.discord_rpc = None
                self.discord_rpc_client_id = None
                threading.Thread(target=rpc.close, daemon=True).start()
        self.rpc_results.put((error, activity is not None))

    def _poll_rpc_result(self):
        if self.closing:
            return
        try:
            error, active = self.rpc_results.get_nowait()
        except queue.Empty:
            pass
        else:
            self._rpc_finished(error, active)
        self.after(100, self._poll_rpc_result)

    def _rpc_finished(self, error: str | None, active: bool):
        self.rpc_busy = False
        if self.closing:
            return
        if error:
            self.status_button.configure(state="normal")
            self.active = not active
            self.canvas.itemconfigure(self.status_label,
                                      text="НЕ УДАЛОСЬ ВКЛЮЧИТЬ СТАТУС" if active else "НЕ УДАЛОСЬ ОТКЛЮЧИТЬ СТАТУС")
            if self.active:
                self.status_button.configure(text="Отключить статус", bg="#c5d0d8", activebackground="#e2e8ed")
            else:
                self.status_button.configure(text="Показать в Discord", bg="#d8dde5", activebackground="#f1f3f6")
            messagebox.showerror(APP_TITLE, error)
        else:
            self.active = active
            if self.active:
                self.reenable_after = 0.0
                self.canvas.itemconfigure(self.status_label, text="СТАТУС ВКЛЮЧЁН")
                self.status_button.configure(state="normal")
                self.status_button.configure(text="Отключить статус", bg="#c5d0d8", activebackground="#e2e8ed")
            else:
                self.canvas.itemconfigure(self.status_label, text="СТАТУС ВЫКЛЮЧЕН")
                self.status_button.configure(text="Показать в Discord", bg="#d8dde5", activebackground="#f1f3f6")
                self.reenable_after = time.monotonic() + 15
                self.status_button.configure(state="disabled")
                self._update_reenable_countdown()

    def _update_reenable_countdown(self):
        if self.closing or self.active or self.rpc_busy:
            return
        remaining = self.reenable_after - time.monotonic()
        if remaining <= 0:
            self.status_button.configure(state="normal", text="Показать в Discord")
            self.reenable_timer = None
            return
        seconds = int(remaining + 0.999)
        self.status_button.configure(state="disabled", text=f"Можно включить через {seconds} сек.")
        self.reenable_timer = self.after(250, self._update_reenable_countdown)

    def _on_close(self):
        self.closing = True
        save_data(self.data)
        if self.discord_rpc is not None:
            rpc = self.discord_rpc
            self.discord_rpc = None
            threading.Thread(target=rpc.close, daemon=True).start()
        self.destroy()


if __name__ == "__main__":
    GameShelf().mainloop()

