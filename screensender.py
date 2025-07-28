#!/usr/bin/env python3
"""
SenderApp – aplikacja wysyłająca przechwycony obraz ekranu do receivera
===========================================================================
Funkcjonalność:
  • Przechwytywanie obrazu z określonego monitora (z wykorzystaniem mss)
  • Kompresja obrazu do formatu JPEG i wysyłanie połączeniami TCP do receivera
  • Łączenie się z receiverem po wykonaniu handshake (GET_NAME)
  • Obsługa poleceń sterujących (start, stop, restart, ping, reboot, shutdown, warning)
    poprzez dedykowany serwer kontroli TCP
  • Wyświetlenie ostrzeżenia (overlay) przy poleceniu "warning" (zablokowanie klawiatury/myszy)

Przykładowe użycie:
  Uruchom skrypt screensender.py – aplikacja uruchomi wewnętrzny serwer kontroli 
  oraz rozpocznie pętlę przechwytywania i wysyłania obrazu.
"""

import socket
import threading
import struct
import mss
import cv2
import time
import os
import numpy as np
import subprocess
import uuid
import tkinter as tk

# ==========================
# Klasa SenderApp
# ==========================
class SenderApp:
    def __init__(self, monitor_index=1):
        # --- KONFIGURACJA ---
        self.SEND_PORT     = 5001               # Port, na który receiver odbiera obraz
        self.SPECIAL_PORT  = self.SEND_PORT + 5 # Port do wysyłki specjalnych poleceń
        self.RECEIVE_PORT  = self.SEND_PORT + 10 # Port, na którym sender nasłuchuje poleceń kontrolnych
        self.monitor_index = monitor_index      # Numer monitora do przechwytywania

        # --- STAN APLIKACJI ---
        self.current_target    = None  # Docelowy adres IP (receiver)
        self.sending           = False # Flaga informująca, czy obecnie wysyłamy obraz
        self.restart_requested = False # Flaga do wywołania restartu połączenia
        self.sock              = None  # Socket wykorzystywany do wysyłania obrazu
        self.monitorThread     = None  # Wątek monitorujący kartę Firefox

        # --- KONTENERY ---
        self.blacklist = [] # Kontener zawierający zablokowane strony

        self.lock = threading.Lock()

    # --- FUNKCJE LISTINGU/OBSŁUGI URZĄDZEŃ ---
    def listDevices(self):
        """
        Zwraca słownik: nazwa urządzenia -> jego identyfikator (ID)
        na podstawie wyników polecenia 'xinput list --name-only'.
        """
        out = subprocess.check_output(["xinput", "list", "--name-only"]).decode().splitlines()
        ids = {}
        for name in out:
            try:
                idx = subprocess.check_output(["xinput", "list", name]).decode().split("id=")[1].split()[0]
                ids[name] = idx
            except Exception:
                continue
        return ids

    def disableDevices(self, dev_ids):
        """Wyłącza (disable) urządzenia o podanych identyfikatorach."""
        for did in dev_ids:
            subprocess.call(["xinput", "disable", did])

    def enableDevices(self, dev_ids):
        """Włącza (enable) urządzenia o podanych identyfikatorach."""
        for did in dev_ids:
            subprocess.call(["xinput", "enable", did])

    def showOverlay(self, duration=5000):
        """
        Wyświetla pełnoekranowy overlay ostrzegawczy na określony czas
        oraz blokuje klawiaturę, mysz i touchpad.
        Po czasie overlay zamyka się i przywraca urządzenia.
        """
        devices = self.listDevices()
        toBlock = [did for name, did in devices.items()
                   if "keyboard" in name.lower() or "mouse" in name.lower() or "touchpad" in name.lower()]
        self.disableDevices(toBlock)

        root = tk.Tk()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        root.geometry(f"{screen_w}x{screen_h}+0+0")
        root.configure(bg="red")
        tk.Label(root,
                 text="WYKRYTO PRÓBĘ OSZUSTWA\nJEST TO OSTRZEŻENIE",
                 fg="white", bg="red", font=("Arial", 64, "bold")
                 ).place(relx=0.5, rely=0.5, anchor="center")

        def teardown():
            root.destroy()
            self.enableDevices(toBlock)
        root.after(duration, teardown)
        root.mainloop()

    # --- DETEKCJA OTWARTEJ KARTY FIREFOX ---
    def detectFirefoxTab(self):
        """
        Próbuje pobrać tytuł aktywnego okna za pomocą xdotool.
        Jeśli tytuł zawiera ciąg 'Firefox', uznajemy, że dotyczy on otwartej karty.
        """
        try:
            title = subprocess.check_output("xdotool getactivewindow getwindowname", shell=True).decode().strip()
            if "Firefox" in title:
                return title
            else:
                return "Brak aktywnej karty Firefox"
        except Exception as e:
            return f"Błąd wykrywania Firefox: {e}"
        
    def monitorFirefox(self):
        """
        Co sekundę sprawdza, jaka karta Firefoxa jest aktywna.
        Działa dopóki wysyłanie (`self.sending`) trwa i połączenie (`self.sock`) jest aktywne.
        Jeśli aktywna karta jest uznana za zakazaną, zostaje zamknięta
        """
        while self.sending and self.sock is not None:
            firefoxTab = self.detectFirefoxTab()
            if self.blacklist:
                firefoxTab = firefoxTab.lower()
                for forbidden in self.blacklist:
                    if forbidden in firefoxTab:
                        print(f"[CTL] Wykryto zakazaną stronę: {forbidden}")
                        subprocess.run("xdotool windowactivate $(xdotool search --onlyvisible --class Firefox | head -n 1)", shell=True)
                        subprocess.run("xdotool key ctrl+w", shell=True)
                        try:
                            with socket.create_connection((self.current_target, self.SPECIAL_PORT), timeout=5) as s:
                                s.sendall(("blacklist " + forbidden).encode("utf-8"))
                        except Exception as e:
                            print("[CTL] Błąd przy wysyłaniu komunikatu:", e)
            time.sleep(1)
        self.monitorThread = None


    # --- SERVER KONTROLNY ---
    def get_mac_address(self):
        """
        Zwraca adres MAC urządzenia w postaci ciągu znaków.
        """
        node = uuid.getnode()
        return ':'.join(f'{(node >> ele) & 0xff:02x}' for ele in range(40, -1, -8))

    def start_control_server(self):
        """
        Uruchamia serwer TCP nasłuchujący poleceń kontrolnych.
        Obsługuje komendy: start, stop, restart, ping, reboot, shutdown, warning.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", self.RECEIVE_PORT))
        srv.listen(5)
        print(f"[CTL] Serwer kontroli nasłuchuje na porcie {self.RECEIVE_PORT}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.control_worker, args=(conn,), daemon=True).start()

    def control_worker(self, conn):
        """
        Obsługuje połączenie kontrolne – odbiera komendę, wykonuje ją i wysyła odpowiedź.
        Komendy:
          start <ip>: rozpoczyna wysyłanie obrazu do podanego IP
          stop: zatrzymuje wysyłanie
          restart: restartuje połączenie
          ping: odpowiada pong
          reboot: restartuje system
          shutdown: wyłącza system
          warning: uruchamia overlay ostrzegawczy
        """
        global current_target, sending, restart_requested, sock
        cmd = conn.recv(100).decode().strip()
        parts = cmd.split()
        action = parts[0].lower()
        print(f"[CTL] Otrzymano polecenie: {cmd}")

        if action == "start" and len(parts) == 2:
            ip = parts[1]
            if not self.sending:
                self.current_target = ip
                self.sending = True
                print(f"[CTL] start → łączę do {ip}")
            else:
                print("[CTL] start zignorowany – już nadaję")
                
        elif action == "stop":
            if self.sending:
                self.sending = False
                if self.sock:
                    self.sock.close()
                    self.sock = None
                print("[CTL] stop → zamykam połączenie i pauzuję")
            else:
                print("[CTL] stop zignorowany – nic nie nadaję")

        elif action == "restart":
            if self.sending:
                self.restart_requested = True
                print("[CTL] restart → wstrzymaj, odczekaj 5s i połącz ponownie")
            else:
                print("[CTL] restart zignorowany – nic nie nadaję")

        elif action == "ping":
            print("[CTL] ping - odsyłam pong")
            try:
                conn.sendall(b"pong\n")
            except Exception as e:
                print(f"[CTL] błąd wysyłania pong: {e}")

        elif action == "reboot":
            print("[CTL] reboot - restart systemu")
            try:
                os.system('sudo systemctl reboot')
                conn.sendall(b"zrestartowano system\n")
            except Exception as e:
                print(f"[CTL] błąd wysyłania reboot: {e}")

        elif action == "shutdown":
            print("[CTL] shutdown - wyłączanie systemu")
            try:
                os.system('sudo /sbin/shutdown -h now')
                conn.sendall(b"wylaczono system\n")
            except Exception as e:
                print(f"[CTL] błąd wysyłania shutdown: {e}")

        elif action == "warning":
            print("[CTL] warning - aktywowano ostrzeżenie")
            try:
                conn.sendall(b"aktywowano ostrzezenie\n")
                self.showOverlay(5000)
            except Exception as e:
                print(f"[CTL] błąd wysyłania warning: {e}")

        elif action == "shell":
            shellCommand = " ".join(parts[1:])
            print(f"[CTL] shell - aktywowano komendę: {shellCommand}")
            try:
                output = subprocess.check_output(shellCommand, shell=True, stderr=subprocess.STDOUT)
                res = output.decode()
                conn.sendall((shellCommand + ": " + res + "\n").encode("utf-8"))
            except subprocess.CalledProcessError as e:
                print(f"[CTL] błąd wykonania shell: {e}")

        elif action == "url":
            destination = " ".join(parts[1:])
            urlLink = "firefox --new-tab " + destination
            print(f"[CTL] url - aktywowano komendę: {urlLink}")
            try:
                conn.sendall(("otworzono link: " + destination + "\n").encode("utf-8"))
                output = subprocess.check_output(urlLink, shell=True, stderr=subprocess.STDOUT)
                res = output.decode()
            except subprocess.CalledProcessError as e:
                print(f"[CTL] błąd wykonania url: {e}")

        elif action == "blacklist":
            self.blacklist = [arg.lower() for arg in parts[1:]]
            print(f"[CTL] Blacklista ustawiona: {', '.join(self.blacklist) if self.blacklist else 'pusta'}")
            conn.sendall(("blacklista ustawiona: " + ", ".join(self.blacklist) + "\n").encode("utf-8"))

        else:
            print(f"[CTL] nieznane polecenie: {cmd}")
        conn.close()

    # --- HELPERY DO HANDSHAKE Z RECEIVEREM ---
    def connect_to_receiver(self, server_ip):
        """
        Próbuje połączyć się z receiverem pod podanym adresem IP.
        Realizuje handshake: odbiera GET_NAME i wysyła (hostname, MAC).
        """
        mac = self.get_mac_address()
        hostname = socket.gethostname()
        info = f"{hostname},{mac}".encode()

        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((server_ip, self.SEND_PORT))
                prompt = s.recv(1024)
                if prompt == b"GET_NAME":
                    s.sendall(info)
                    print(f"[NET] Handshake OK z {server_ip}")
                    return s
                else:
                    print(f"[NET] Nieoczekiwany prompt: {prompt!r}")
                    s.close()
            except Exception as e:
                print(f"[NET] Błąd łączenia do {server_ip}: {e}, retry...")
                time.sleep(2)

    # --- PĘTLA WYSYŁANIA OBRAZU ---
    def send_loop(self):
        """
        Główna pętla wysyłania – przechwytuje ekran, przetwarza obraz,
        koduje klatki do JPEG i wysyła je do receivera.
        """
        global sock, sending, restart_requested
        # Czekamy na dostępność zmiennej DISPLAY
        while True:
            disp = subprocess.getoutput("who | grep '(:' | awk '{print $NF}' | tr -d '()'")
            if disp:
                os.environ["DISPLAY"] = disp
                break
            time.sleep(5)

        with mss.mss() as sct:
            monitors = sct.monitors
            monitor = monitors[min(self.monitor_index, len(monitors)-1)]
            print(f"[CAP] Przechwytuję monitor #{self.monitor_index}: {monitor}")

            while True:
                # (1) Jeśli nie nadaję – pauzuj
                if not self.sending:
                    time.sleep(0.1)
                    continue

                # (2) Przy restart – zamknij połączenie, odczekaj i wyzeruj restart_requested
                if self.restart_requested:
                    if self.sock:
                        self.sock.close()
                        self.sock = None
                    time.sleep(5)
                    self.restart_requested = False
                    self.monitorThread = None

                # (3) Jeśli brak połączenia – spróbuj połączyć
                if self.sock is None and self.current_target:
                    self.sock = self.connect_to_receiver(self.current_target)
                    # Po nawiązaniu połączenia – wykonaj wykrywanie aktywnej karty FireFox, jeżeli wcześniej nie wykryto
                    if self.sock is not None and self.monitorThread is None:
                        self.monitorThread = threading.Thread(target=self.monitorFirefox, daemon=True)
                        self.monitorThread.start()

                # (4) Jeżeli nadal brak sock – odczekaj
                if self.sock is None:
                    time.sleep(0.1)
                    continue

                try:
                    # Przechwycenie ekranu
                    img = sct.grab(monitor)
                    # Konwersja RGBA do RGB
                    frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGBA2RGB)
                    # Zmniejszenie rozdzielczości (opcjonalnie)
                    frame = cv2.resize(frame, (frame.shape[1]//2, frame.shape[0]//2))
                    # Kompresja do JPEG
                    ret, jpg = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                    data = jpg.tobytes()

                    # Wysyłka: najpierw długość, potem dane
                    if self.sock:
                        self.sock.sendall(struct.pack(">L", len(data)) + data)
                    else:
                        raise AttributeError("sock is None")

                    time.sleep(1/15)

                except (ConnectionResetError, BrokenPipeError, socket.error, AttributeError) as e:
                    print(f"[NET] Utracono połączenie lub brak sock: {e}")
                    self.sending = False
                    if self.sock:
                        self.sock.close()
                    self.sock = None
                    self.monitorThread = None

    # --- URUCHOMIENIE APLIKACJI ---
    def run(self):
        """
        Uruchamia serwer kontroli w osobnym wątku oraz pętlę wysyłania obrazu.
        """
        threading.Thread(target=self.start_control_server, daemon=True).start()
        self.send_loop()


# ==========================
# Start aplikacji
# ==========================
if __name__ == "__main__":
    app = SenderApp(monitor_index=1)
    app.run()
