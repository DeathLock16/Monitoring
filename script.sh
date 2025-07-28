#!/bin/bash

SRC_SCRIPT="/home/put/Desktop/dist/screensender.sh"
SRC_UNIT="/home/put/Desktop/screensender.service"
USERNAME="put"
SSHPASS="put"

for i in {29..46}; do
  IP="150.254.129.$i"
  echo "— Aktualizacja $IP —"

  # 1) Zabijamy poprzedni screensender.sh
  sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no put@"$IP" \
    'pkill -f screensender.sh 2>/dev/null || true'

  # 2) Przesyłamy pliki do /tmp
  sshpass -p "$SSHPASS" scp -o StrictHostKeyChecking=no \
    "$SRC_SCRIPT" put@"$IP":/tmp/screensender.sh
  sshpass -p "$SSHPASS" scp -o StrictHostKeyChecking=no \
    "$SRC_UNIT" put@"$IP":/tmp/screensender.service

  # 3) Wykonujemy wszystkie operacje z sudo
  sshpass -p "$SSHPASS" ssh -tt -o StrictHostKeyChecking=no put@"$IP" <<EOF
echo "$SSHPASS" | sudo -S systemctl unmask screensender.service
echo "$SSHPASS" | sudo -S mv /tmp/screensender.sh /usr/local/bin/screensender.sh
echo "$SSHPASS" | sudo -S chmod 755 /usr/local/bin/screensender.sh
echo "$SSHPASS" | sudo -S mv /tmp/screensender.service /etc/systemd/system/screensender.service
echo "$SSHPASS" | sudo -S chmod 644 /etc/systemd/system/screensender.service
echo "$SSHPASS" | sudo -S systemctl daemon-reload
echo "$SSHPASS" | sudo -S systemctl enable screensender.service
echo "$SSHPASS" | sudo -S systemctl restart screensender.service

# 4) Dodajemy użytkownika do sudoers (bez hasła dla reboot i shutdown)
echo "$SSHPASS" | sudo -S bash -c "echo '$USERNAME ALL=(ALL) NOPASSWD: /bin/systemctl reboot' | tee -a /etc/sudoers"
echo "$SSHPASS" | sudo -S bash -c "echo '$USERNAME ALL=(ALL) NOPASSWD: /sbin/shutdown' | tee -a /etc/sudoers"

# 5) Dodajemy uprawnienie do xinput (blokada/odblokowanie urządzeń)
echo "$SSHPASS" | sudo -S bash -c "echo '$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/xinput disable *, /usr/bin/xinput enable *' | tee -a /etc/sudoers"

# 6) Instalacja xdotool (aktualizacja repozytoriów i instalacja pakietu)
echo "$SSHPASS" | sudo -S apt-get update
echo "$SSHPASS" | sudo -S apt-get install -y xdotool

exit
EOF

  echo "✅ $IP – skrypt i unit wgrane, serwis odblokowany, wpis sudoers dodany, xdotool zainstalowany."
done

