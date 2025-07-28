import tkinter as tk
from PIL import Image, ImageTk
import threading, socket, struct, cv2, numpy as np, time, datetime, ipaddress, queue, subprocess
import socket as pysocket
import os

class ReceiverApp:
    def __init__(self):
        # === KONFIGURACJA PODSTAWOWA ===
        self.HOST = "0.0.0.0"
        self.RECEIVE_PORT = 5001
        self.SPECIAL_PORT = self.RECEIVE_PORT + 5
        self.SEND_PORT = self.RECEIVE_PORT + 10
        self.MAX_CLIENTS = 20
        self.STALE_THRESHOLD = 5.0
        self.THUMB_W, self.THUMB_H = 160, 120

        # === STAN APLIKACJI ===
        self.clients            = [None] * self.MAX_CLIENTS     # sockety lub None
        self.hostmac2slot       = {}                            # (host, mac) -> slot
        self.PCNames            = {}                            # slot -> (host, ip, mac)
        self.frames             = {}                            # slot -> (np.ndarray, timestamp)
        self.thumbnailCache     = {}                            # slot -> PhotoImage dla GUI
        self.recording          = {}                            # slot -> (Queue, Thread, Popen) dla nagrywania
        self.blacklistDomains   = [                             # zablokowane domeny jako lowercase
            "deepseek",
            "chatgpt",
            "copilot"
        ]

        self.lock = threading.Lock()

        # === INTERFEJS GRAFICZNY ===
        self.root = tk.Tk()
        self.root.title("Podgląd ekranu")
        self.root.resizable(False, False)

        self.controlFrame = tk.Frame(self.root, bg="lightgrey", pady=4)
        self.controlFrame.grid(row=0, column=0, columnspan=5, sticky="ew")

        tk.Label(self.controlFrame, text="Podsieć:", bg="lightgrey").pack(side="left", padx=5)
        self.subnet_var = tk.StringVar()
        self.subnet_entry = tk.Entry(self.controlFrame, textvariable=self.subnet_var, width=20)
        self.subnet_entry.pack(side="left")

        tk.Label(self.controlFrame, text="Infix:", bg="lightgrey").pack(side="left", padx=5)
        self.infix_var = tk.StringVar()
        self.infix_entry = tk.Entry(self.controlFrame, textvariable=self.infix_var, width=20)
        self.infix_entry.pack(side="left")

        # Przyciskowe elementy sterujące
        self.startButton = tk.Button(self.controlFrame, text="Start", command=self.startConnection)
        self.stopButton = tk.Button(self.controlFrame, text="Stop", command=self.stopConnection)
        self.restartButton = tk.Button(self.controlFrame, text="Restart", command=self.restartConnection)
        self.broadcastButton = tk.Button(self.controlFrame, text="BroadCast")
        self.broadcastButton.bind("<Button-1>", self.showBroadcastMenu)

        self.startButton.pack(side="left", padx=5)
        self.stopButton.pack(side="left", padx=5)
        self.restartButton.pack(side="left", padx=5)
        self.broadcastButton.pack(side="right", padx=5)

        # Menu kontekstowe dla pojedynczych klientów
        self.contextMenu = tk.Menu(self.root, tearoff=0)
        self.contextMenu.add_command(label="Ping", command=lambda: None)
        self.contextMenu.add_command(label="Reboot", command=lambda: None)
        self.contextMenu.add_command(label="Shutdown", command=lambda: None)
        self.contextMenu.add_command(label="Warning", command=lambda: None)
        self.contextMenu.add_command(label="Record", command=lambda: None)
        self.contextMenu.add_command(label="Shell", command=lambda: None)
        self.contextMenu.add_command(label="URL", command=lambda: None)
        self.contextMenu.add_command(label="BlackList", command=lambda: None)
        self.contextMenu.bind("<FocusOut>", lambda e: self.hideMenu())

        # Menu broadcast – dla wszystkich klientów jednocześnie
        self.broadcastMenu = tk.Menu(self.root, tearoff=0)
        self.broadcastMenu.add_command(label="Ping", command=lambda: None)
        self.broadcastMenu.add_command(label="Reboot", command=lambda: None)
        self.broadcastMenu.add_command(label="Shutdown", command=lambda: None)
        self.broadcastMenu.add_command(label="Record", command=lambda: None)
        self.broadcastMenu.add_command(label="Shell", command=lambda: None)
        self.broadcastMenu.add_command(label="URL", command=lambda: None)
        self.broadcastMenu.add_command(label="BlackList", command=lambda: None)
        self.broadcastMenu.bind("<FocusOut>", lambda e: self.hideBroadcastMenu())

        # Obszary wyświetlania (sloty)
        self.tiles = []   # label do miniatur
        self.labels = []  # label do informacji

        for slot in range(self.MAX_CLIENTS):
            r, c = divmod(slot, 5)
            frame = tk.Frame(self.root, width=self.THUMB_W, height=self.THUMB_H,
                             bg="black", relief="solid", borderwidth=3)
            frame.grid(row=r+1, column=c, padx=2, pady=2, sticky="nw")
            frame.grid_propagate(False)

            tile = tk.Label(frame, bg="black", fg="red", font=("Arial", 16),
                            anchor="center", justify="center", wraplength=self.THUMB_W)
            tile.pack(fill="both", expand=True)
            tile.bind("<Button-1>", lambda e, s=slot: self.showFullscreen(s))
            tile.bind("<Button-3>", lambda e, s=slot: self.showMenu(e, s))
            self.tiles.append(tile)

            lbl = tk.Label(frame, fg="white", bg="black", font=("Arial", 9), text="")
            lbl.pack(side="bottom", fill="x")
            self.labels.append(lbl)

        # Ustawienie domyślnej podsieci na podstawie lokalnego IP
        self.subnet_var.set('.'.join(self.getLocalIP().split('.')[:3]) + '.0/24')
        
        # Bindowanie klawisza Enter
        self.root.bind("<Return>", self.onEnter)
        
        # Uruchomienie serwera w osobnym wątku i odświeżanie GUI
        threading.Thread(target=self.startServer, daemon=True).start()
        threading.Thread(target=self.startSpecialListener, daemon=True).start()
        self.root.after(500, self.updateDisplay)

        # Zmienna dla pełnoekranowego odtwarzania obrazu
        self.fullscreenWindow = None
        self.fullscreenLabel = None

    # ==========================
    # METODY POMOCNICZE & KOMENDY INDYWIDUALNE
    # ==========================

    def getLocalIP(self):
        s = pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"
        finally:
            s.close()

    def enterShellCommand(self):
        shellWindow = tk.Toplevel(self.root)
        shellWindow.title("Shell Command")
        shellWindow.geometry("400x150")
        shellWindow.resizable(False, False)

        tk.Label(shellWindow, text="Wpisz polecenie do wykonania").pack(pady=10)
        cmdEntry = tk.Entry(shellWindow, width=50)
        cmdEntry.pack(pady=5)
        cmdEntry.focus_set()

        result = {}

        def onExecute(event=None):
            result["command"] = cmdEntry.get().strip()
            shellWindow.destroy()

        tk.Button(shellWindow, text="Wykonaj", command=onExecute).pack(pady=10)
        shellWindow.bind("<Return>", onExecute)
        self.root.wait_window(shellWindow)
        return result.get("command", "")
    
    def enterURL(self):
        urlWindow = tk.Toplevel(self.root)
        urlWindow.title("Open URL")
        urlWindow.geometry("400x150")
        urlWindow.resizable(False, False)

        tk.Label(urlWindow, text="Wpisz link do otwarcia").pack(pady=10)
        urlEntry = tk.Entry(urlWindow, width=50)
        urlEntry.pack(pady=5)
        urlEntry.focus_set()

        result = {}

        def onExecute(event=None):
            result["url"] = urlEntry.get().strip()
            urlWindow.destroy()

        tk.Button(urlWindow, text="Wykonaj", command=onExecute).pack(pady=10)
        urlWindow.bind('<Return>', onExecute)
        self.root.wait_window(urlWindow)
        return result.get("url", "")
    
    def enterBlacklist(self):
        blacklistWindow = tk.Toplevel(self.root)
        blacklistWindow.title("Block Domain")
        blacklistWindow.geometry("400x150")
        blacklistWindow.resizable(False, False)

        tk.Label(blacklistWindow, text="Wpisz domeny do zablokowania").pack(pady=10)
        blacklistEntry = tk.Entry(blacklistWindow, width=50)
        blacklistEntry.insert(0, " ".join(self.blacklistDomains))
        blacklistEntry.pack(pady=5)
        blacklistEntry.focus_set()

        result = {}

        def onExecute(event=None):
            result["blacklist"] = blacklistEntry.get().strip()
            blacklistWindow.destroy()

        tk.Button(blacklistWindow, text="Wykonaj", command=onExecute).pack(pady=10)
        blacklistWindow.bind('<Return>', onExecute)
        self.root.wait_window(blacklistWindow)
        return result.get("blacklist", "")

    def CMD_Ping(self, slot):
        info = self.PCNames.get(slot)
        if not info:
            print(f"[PING] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info
        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(b"ping")
                resp = s.recv(1024).decode().strip()
            print(f"[PING] od {ip}: {resp}")
        except Exception as e:
            print(f"[PING] błąd wysyłki ping do {ip}: {e}")

    def CMD_Reboot(self, slot):
        info = self.PCNames.get(slot)
        if not info:
            print(f"[REBOOT] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info
        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(b"reboot")
                resp = s.recv(1024).decode().strip()
            print(f"[REBOOT] od {ip}: {resp}")
        except Exception as e:
            print(f"[REBOOT] błąd wysyłki reboot do {ip}: {e}")

    def CMD_Shutdown(self, slot):
        info = self.PCNames.get(slot)
        if not info:
            print(f"[SHUTDOWN] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info
        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(b"shutdown")
                resp = s.recv(1024).decode().strip()
            print(f"[SHUTDOWN] od {ip}: {resp}")
        except Exception as e:
            print(f"[SHUTDOWN] błąd wysyłki shutdown do {ip}: {e}")

    def CMD_Warning(self, slot):
        info = self.PCNames.get(slot)
        if not info:
            print(f"[WARNING] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info
        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(b"warning")
                resp = s.recv(1024).decode().strip()
            print(f"[WARNING] od {ip}: {resp}")
        except Exception as e:
            print(f"[WARNING] błąd wysyłki warning do {ip}: {e}")

    def CMD_Record(self, slot):
        # Jeśli nagrywanie już trwa – zatrzymaj je
        if slot in self.recording:
            q, thr, proc = self.recording.pop(slot)
            q.put(None)
            thr.join()
            proc.stdin.close()
            proc.wait()
            print(f"[RECORD] slot {slot} – zakończono nagrywanie")
            return

        info = self.PCNames.get(slot)
        if not info:
            print(f"[RECORD] slot {slot} – brak klienta")
            return
        _, ip, _ = info

        with self.lock:
            frm = self.frames.get(slot)
        if not frm:
            print(f"[RECORD] slot {slot} – brak obrazu do nagrania")
            return
        frame, _ = frm
        h, w = frame.shape[:2]

        now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
        recordDir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recordings")
        fname = f"{ip}_{now}.mp4"

        if not os.path.exists(recordDir):
            os.makedirs(recordDir)

        cmd = [
            "ffmpeg", "-y",
            "-loglevel", "error",
            "-f", "mjpeg",
            "-r", "10",
            "-i", "pipe:0",
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-crf", "35",
            os.path.join(recordDir, fname)
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        q = queue.Queue(maxsize=100)
        def writer():
            while True:
                buf = q.get()
                if buf is None:
                    break
                try:
                    proc.stdin.write(buf)
                except Exception as ex:
                    print(f"[RECORD] błąd zapisu do FFmpeg: {ex}")
                    break
            proc.stdin.close()
            proc.wait()
        thr = threading.Thread(target=writer, daemon=True)
        thr.start()
        self.recording[slot] = (q, thr, proc)
        print(f"[RECORD] slot {slot} – rozpoczęto nagrywanie → {fname}")

    def CMD_Shell(self, slot, command=None):
        if command == None:
            command = self.enterShellCommand()
        print(f"[SHELL] Wpisana komenda: {command}")
        if not command:
            print(f"[SHELL] Komenda pusta - przerwanie")
            return
                    
        info = self.PCNames.get(slot)
        if not info:
            print(f"[SHELL] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info

        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(("shell " + command).encode("utf-8"))
                resp = s.recv(1024).decode().strip()
            print(f"[SHELL] od {ip}: {resp}")
        except Exception as e:
            print(f"[SHELL] błąd wysyłki shell do {ip}: {e}")

    def CMD_Url(self, slot, url=None):
        if url == None:
            url = self.enterURL()
        print(f"[URL] Wpisana komenda: {url}")
        if not url:
            print(f"[URL] Komenda pusta - przerwanie")
            return
                    
        info = self.PCNames.get(slot)
        if not info:
            print(f"[URL] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info

        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(("url " + url).encode("utf-8"))
                resp = s.recv(1024).decode().strip()
            print(f"[URL] od {ip}: {resp}")
        except Exception as e:
            print(f"[URL] błąd wysyłki url do {ip}: {e}")

    def CMD_Blacklist(self, slot, blacklist = None):
        """
        Otwiera okienko, w którym można edytować listę blokowanych domen.
        Pole jest wstępnie uzupełnione zawartością self.blacklistDomains oddzieloną spacjami.
        Po zatwierdzeniu wysyła do wskazanego klienta komendę w formacie:
          blacklist link link link ...
        """
        if blacklist == None:
            blacklist = self.enterBlacklist()
        print(f"[BLACKLIST] Wpisana komenda: {blacklist}")
        if not blacklist:
            print(f"[BLACKLIST] Komenda pusta - przerwanie")
            return
                    
        info = self.PCNames.get(slot)
        if not info:
            print(f"[BLACKLIST] slot {slot} pusty - nic nie wysyłam")
            return
        _, ip, _ = info

        try:
            with socket.create_connection((ip, self.SEND_PORT), timeout=1) as s:
                s.sendall(("blacklist " + blacklist).encode("utf-8"))
                resp = s.recv(1024).decode().strip()
            print(f"[BLACKLIST] od {ip}: {resp}")
        except Exception as e:
            print(f"[BLACKLIST] błąd wysyłki blacklist do {ip}: {e}")


    # --- KOMENDY BROADCAST ( WSZYSTKIE KOMPUTERY )

    def CMD_Broadcast_Ping(self):
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Ping(slot)

    def CMD_Broadcast_Reboot(self):
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Reboot(slot)

    def CMD_Broadcast_Shutdown(self):
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Shutdown(slot)

    def CMD_Broadcast_Record(self):
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Record(slot)

    def CMD_Broadcast_Shell(self):
        command = self.enterShellCommand()
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Shell(slot, command)

    def CMD_Broadcast_Url(self):
        url = self.enterURL()
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Url(slot, url)

    def CMD_Broadcast_Blacklist(self):
        blacklist = self.enterBlacklist()
        for slot, conn in enumerate(self.clients):
            if conn is not None:
                self.CMD_Blacklist(slot, blacklist)

    # ==========================
    # NASŁUCHIWANIE POLECEŃ SPECJALNYCH
    # ==========================
    def startSpecialListener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.HOST, self.SPECIAL_PORT))
        sock.listen(5)
        print(f"[SPECIALPORT] Nasłuchuje na porcie {self.SPECIAL_PORT}...")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self.handleSpecialMessage, args=(conn, addr), daemon=True).start()

    def handleSpecialMessage(self, conn, addr):
        try:
            data = conn.recv(1024).decode("utf-8").strip()
            if data.startswith("blacklist"):
                print(f"[BLACKLIST] {addr[0]}: Zablokowano witrynę {data[10:]}")
            else:
                print(f"[SPECIAL] {addr[0]}: Odebrano {data}")
        except Exception as e:
            print(f"[SPECIAL] Błąd przy odbiorze: {e}")
        finally:
            conn.close()

    # ==========================
    # MENU I INTERFEJS
    # ==========================
    def hideMenu(self, event=None):
        self.contextMenu.unpost()
        self.root.unbind("<Button-1>")
        self.root.unbind("<Button-3>")

    def showMenu(self, event, slot):
        self.contextMenu.entryconfigure(0, command=lambda: self.CMD_Ping(slot))
        self.contextMenu.entryconfigure(1, command=lambda: self.CMD_Reboot(slot))
        self.contextMenu.entryconfigure(2, command=lambda: self.CMD_Shutdown(slot))
        self.contextMenu.entryconfigure(3, command=lambda: self.CMD_Warning(slot))
        self.contextMenu.entryconfigure(4, command=lambda: self.CMD_Record(slot))
        self.contextMenu.entryconfigure(5, command=lambda: self.CMD_Shell(slot))
        self.contextMenu.entryconfigure(6, command=lambda: self.CMD_Url(slot))
        self.contextMenu.entryconfigure(7, command=lambda: self.CMD_Blacklist(slot))
        self.contextMenu.tk_popup(event.x_root, event.y_root)
        self.contextMenu.grab_release()
        self.root.bind("<Button-1>", self.hideMenu)
        self.root.bind("<Button-3>", self.hideMenu)
        return "break"

    def hideBroadcastMenu(self, event=None):
        self.broadcastMenu.unpost()
        self.root.unbind("<Button-1>")
        self.root.unbind("<Button-3>")

    def showBroadcastMenu(self, event):
        self.broadcastMenu.entryconfigure(0, command=self.CMD_Broadcast_Ping)
        self.broadcastMenu.entryconfigure(1, command=self.CMD_Broadcast_Reboot)
        self.broadcastMenu.entryconfigure(2, command=self.CMD_Broadcast_Shutdown)
        self.broadcastMenu.entryconfigure(3, command=self.CMD_Broadcast_Record)
        self.broadcastMenu.entryconfigure(4, command=self.CMD_Broadcast_Shell)
        self.broadcastMenu.entryconfigure(5, command=self.CMD_Broadcast_Url)
        self.broadcastMenu.entryconfigure(6, command=self.CMD_Broadcast_Blacklist)
        self.broadcastMenu.tk_popup(event.x_root, event.y_root)
        self.broadcastMenu.grab_release()
        self.root.bind("<Button-1>", self.hideBroadcastMenu)
        self.root.bind("<Button-3>", self.hideBroadcastMenu)
        return "break"

    def onEnter(self, event):
        w = self.root.focus_get()
        if w in (self.startButton, self.stopButton, self.restartButton):
            w.invoke()

    # ==========================
    # OBSŁUGA POŁĄCZEŃ I SERWER
    # ==========================
    def manageConnection(self, action):
        net_str = self.subnet_var.get().strip()
        infix = self.infix_var.get().strip().lower()
        try:
            net = ipaddress.ip_network(net_str, strict=False)
        except Exception as e:
            print("Błędna podsieć:", e)
            return

        local_ip = self.getLocalIP()
        arg = f"start {local_ip}" if action == "start" else action

        for ip in net.hosts():
            try:
                host = pysocket.gethostbyaddr(str(ip))[0]
            except:
                host = ""
            if infix and infix not in host.lower():
                continue
            try:
                with socket.create_connection((str(ip), self.SEND_PORT), timeout=1) as s:
                    s.sendall(arg.encode("utf-8"))
                    if arg.startswith("ping"):
                        resp = s.recv(1024).decode().strip()
                        print(f"[PONG] od {ip}: {resp}")
                print(f"[+] {ip} ({host}): send `{arg}`")
            except Exception as ex:
                print(f"[-] {ip} ({host}): connection error -> {ex}")

    def handleClient(self, conn, addr):
        # Handshake: pobranie danych identyfikacyjnych
        conn.sendall(b"GET_NAME")
        data = conn.recv(1024).decode().strip()
        try:
            host, mac = data.split(",", 1)
        except ValueError:
            conn.close()
            return
        ip, _ = conn.getpeername()

        # Przydzielanie slotu
        key = (host, mac)
        with self.lock:
            if key in self.hostmac2slot:
                slot = self.hostmac2slot[key]
            else:
                try:
                    slot = self.clients.index(None)
                except ValueError:
                    conn.close()  # brak wolnych slotów
                    return
                self.hostmac2slot[key] = slot

            self.clients[slot] = conn
            self.PCNames[slot] = (host, ip, mac)
            self.frames.pop(slot, None)
            self.thumbnailCache.pop(slot, None)
        print(f"[+] Klient w slocie {slot}: {host}@{ip} MAC={mac}")

        # Odbiór strumienia
        try:
            while True:
                hdr = conn.recv(4)
                if not hdr:
                    raise ConnectionResetError
                length = struct.unpack(">L", hdr)[0]
                buf = b""
                while len(buf) < length:
                    chunk = conn.recv(length - len(buf))
                    if not chunk:
                        raise ConnectionResetError
                    buf += chunk

                arr = np.frombuffer(buf, dtype=np.uint8)
                frame = cv2.imdecode(arr, cv2.COLOR_BGR2RGB)
                with self.lock:
                    self.frames[slot] = (frame, time.time())
                    if slot in self.recording:
                        try:
                            self.recording[slot][0].put_nowait(buf)
                        except queue.Full:
                            pass
        except (ConnectionResetError, ConnectionAbortedError):
            print(f"[-] Klient w slocie {slot} rozłączony.")
            if slot in self.recording:
                q, thr, proc = self.recording.pop(slot)
                q.put(None)
                thr.join()
                proc.stdin.close()
                proc.wait()
                print(f"[RECORD] slot {slot} – rozłączony, nagrywanie zatrzymane")
            return
        finally:
            with self.lock:
                self.clients[slot] = None
                self.PCNames.pop(slot, None)
                self.frames.pop(slot, None)
                self.thumbnailCache.pop(slot, None)
                self.hostmac2slot.pop(key, None)
            conn.close()

    def startServer(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.HOST, self.RECEIVE_PORT))
        sock.listen(self.MAX_CLIENTS)
        print(f"Serwer nasłuchuje na {self.HOST}:{self.RECEIVE_PORT}")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self.handleClient, args=(conn, addr), daemon=True).start()

    # ==========================
    # ODŚWIEŻANIE GUI
    # ==========================
    def updateDisplay(self):
        now = time.time()
        with self.lock:
            snap_names = self.PCNames.copy()
            snap_frames = self.frames.copy()

        for slot in range(self.MAX_CLIENTS):
            tile = self.tiles[slot]
            lbl = self.labels[slot]
            info = snap_frames.get(slot)
            if info and (now - info[1] < self.STALE_THRESHOLD):
                frame_bgr, ts = info
                if frame_bgr is not None and getattr(frame_bgr, 'size', 0) > 0:
                    rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(rgb).resize((self.THUMB_W, self.THUMB_H), Image.BILINEAR)
                    imgTk = ImageTk.PhotoImage(img)
                    self.thumbnailCache[slot] = imgTk
                    tile.config(image=imgTk, text="")
                    tile.image = imgTk
                else:
                    tile.config(image="", text="Brak sygnału", fg="red",
                                font=("Arial", 16), anchor="center", justify="center")
                tile.config(bg="orange" if slot in self.recording else "black")
            else:
                tile.config(image="", text="Brak sygnału",
                            fg="red", font=("Arial", 16), anchor="center", justify="center")
            if slot in snap_names:
                h, ip, m = snap_names[slot]
                lbl.config(text=f"{h}@{ip}\n{m}")
            else:
                lbl.config(text="")
        self.root.after(500, self.updateDisplay)

    def showFullscreen(self, slot):
        if self.fullscreenWindow:
            return
        self.fullscreenWindow = tk.Toplevel(self.root)
        self.fullscreenWindow.attributes("-fullscreen", True)
        self.fullscreenWindow.configure(bg="black")
        self.fullscreenLabel = tk.Label(self.fullscreenWindow, bg="black")
        self.fullscreenLabel.pack(fill="both", expand=True)
        self.fullscreenWindow.bind("<Button-1>", lambda e: self.closeFullscreen())
        self.updateFullscreen(slot)

    def closeFullscreen(self):
        if self.fullscreenWindow:
            self.fullscreenWindow.destroy()
            self.fullscreenWindow = None

    def updateFullscreen(self, slot):
        if not self.fullscreenWindow:
            return
        with self.lock:
            info = self.frames.get(slot)
        if info:
            frame_bgr, ts = info
            rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb).resize((self.fullscreenWindow.winfo_screenwidth(),
                                                self.fullscreenWindow.winfo_screenheight()),
                                               Image.BILINEAR)
            imgTk = ImageTk.PhotoImage(img)
            self.fullscreenLabel.config(image=imgTk)
            self.fullscreenLabel.image = imgTk
        self.fullscreenWindow.after(50, lambda: self.updateFullscreen(slot))

    # ==========================
    # FUNKCJE STERUJĄCE SKANOWANIEM
    # ==========================
    def startConnection(self):
        print("Start", self.subnet_var.get())
        threading.Thread(target=self.manageConnection, args=("start",), daemon=True).start()

    def stopConnection(self):
        print("Stop")
        for slot in list(self.recording.keys()):
            self.CMD_Record(slot)
        threading.Thread(target=self.manageConnection, args=("stop",), daemon=True).start()

    def restartConnection(self):
        print("Restart")
        for slot in list(self.recording.keys()):
            self.CMD_Record(slot)
        threading.Thread(target=self.manageConnection, args=("restart",), daemon=True).start()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ReceiverApp()
    app.run()
