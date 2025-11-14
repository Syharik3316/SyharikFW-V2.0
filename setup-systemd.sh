#!/bin/bash
# Скрипт для настройки systemd unit файла

set -e

# Определяем путь к проекту
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_FILE="/etc/systemd/system/syharikfw@.service"
FIREWALL_BIN="$PROJECT_DIR/firewall"

echo "Настройка systemd unit файла для SyharikFW"
echo "Путь к проекту: $PROJECT_DIR"
echo ""

# Проверяем права root
if [ "$EUID" -ne 0 ]; then 
    echo "Ошибка: Запустите скрипт с правами root (sudo)"
    exit 1
fi

# Проверяем, установлен ли firewall через make install
if [ -f "/usr/local/bin/firewall" ]; then
    echo "Обнаружен firewall в /usr/local/bin/firewall (установлен через make install)"
    FIREWALL_PATH="/usr/local/bin/firewall"
else
    echo "Firewall не найден в /usr/local/bin, используем локальный: $FIREWALL_BIN"
    if [ ! -f "$FIREWALL_BIN" ]; then
        echo "Ошибка: Файл $FIREWALL_BIN не найден!"
        echo "Сначала скомпилируйте проект: make"
        exit 1
    fi
    FIREWALL_PATH="$FIREWALL_BIN"
fi

# Копируем unit файл
echo "Копирование unit файла..."
cp syharikfw@.service "$UNIT_FILE"

# Заменяем пути в unit файле
echo "Обновление ExecStart на $FIREWALL_PATH..."
sed -i "s|ExecStart=/usr/local/bin/firewall|ExecStart=$FIREWALL_PATH|g" "$UNIT_FILE"

echo "Обновление WorkingDirectory на $PROJECT_DIR..."
sed -i "s|WorkingDirectory=/path/to/firewall|WorkingDirectory=$PROJECT_DIR|g" "$UNIT_FILE"

# Перезагружаем systemd
echo "Перезагрузка systemd daemon..."
systemctl daemon-reload

echo ""
echo "Готово! Unit файл настроен."
echo "  ExecStart: $FIREWALL_PATH"
echo "  WorkingDirectory: $PROJECT_DIR"
echo ""
echo "Теперь вы можете:"
echo "  sudo systemctl start syharikfw@eth0    # Запустить для интерфейса eth0"
echo "  sudo systemctl enable syharikfw@eth0   # Включить автозапуск"
echo "  sudo systemctl status syharikfw@eth0   # Проверить статус"
echo ""

