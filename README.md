Руководство по использованию python-скрипта disk-analyzer для анализа дампа диска.
Требования:
   Python 3.7+
   Linux / macOS / Windows (терминал с ANSI‑цветами)
1. Запустить терминал.
2. Установить пакеты git командой apt install git, если ещё не установлены.
3. Склонировать репозиторий командой git clone https://github.com/WarmLand899/disk-analyzer.git
4. Перейти в директорию командой cd disk-analyzer
5. Если есть дамп диска, то запустить скрипт командой python3 disk_analyzer.py ~/<ИМЯ ДАМПА>
6. Если дамп отсуствует, то создать его командой sudo dd if=/dev/sda of=mbr.img bs=512 count=1 (Имя диска обычно sda)
   и запустить скрипт командой python3 disk_analyzer.py ~/mbr.img

