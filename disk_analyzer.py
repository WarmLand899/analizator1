#!/usr/bin/env python3
"""
Анализатор дампа диска Linux
Определяет таблицу разделов (MBR/GPT) и находит первый сектор каждого раздела
"""

import struct
import binascii
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from enum import Enum
from dataclasses import dataclass

# Инициализация цветов для терминала
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    # Фон
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

class PartitionType(Enum):
    MBR = "MBR"
    GPT = "GPT"
    UNKNOWN = "Unknown"

@dataclass
class PartitionEntry:
    """Структура для хранения информации о разделе"""
    number: int
    type: str
    type_code: int
    start_sector: int
    size_sectors: int
    end_sector: int
    size_bytes: int
    size_human: str
    guid: str = ""
    name: str = ""
    attributes: int = 0
    is_active: bool = False

class DiskAnalyzer:
    def __init__(self, disk_image: str, sector_size: int = 512):
        """
        Инициализация анализатора диска
        
        Args:
            disk_image: Путь к файлу дампа диска
            sector_size: Размер сектора (обычно 512 или 4096 байт)
        """
        self.disk_image = disk_image
        self.sector_size = sector_size
        self.partition_type = PartitionType.UNKNOWN
        self.partitions: List[PartitionEntry] = []
        self.boot_signature = ""
        self.disk_size = 0
        
    def analyze(self) -> bool:
        """Основной метод анализа диска"""
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}АНАЛИЗ ДАМПА ДИСКА: {self.disk_image}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        
        try:
            # Получаем размер файла
            self.disk_size = os.path.getsize(self.disk_image)
            print(f"{Colors.GREEN}Размер дампа:{Colors.END} {self.disk_size:,} байт "
                  f"({self.disk_size / (1024**3):.2f} GB)")
            
            with open(self.disk_image, 'rb') as f:
                # Читаем первый сектор
                sector0 = f.read(self.sector_size)
                
                if len(sector0) < self.sector_size:
                    print(f"{Colors.RED}Ошибка: файл слишком мал для анализа{Colors.END}")
                    return False
                
                # Определяем тип таблицы разделов
                self._detect_partition_type(sector0)
                
                # Анализируем в зависимости от типа
                if self.partition_type == PartitionType.MBR:
                    self._analyze_mbr(sector0, f)
                elif self.partition_type == PartitionType.GPT:
                    self._analyze_gpt(sector0, f)
                else:
                    print(f"{Colors.YELLOW}Неизвестная структура диска{Colors.END}")
                    return False
                
                # Показываем hex дамп с раскраской
                self._print_colored_hex_dump(sector0)
                
                # Ищем первый сектор каждого раздела
                self._find_first_sectors()
                
            return True
            
        except FileNotFoundError:
            print(f"{Colors.RED}Файл не найден: {self.disk_image}{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}Ошибка при анализе: {str(e)}{Colors.END}")
            return False
    
    def _detect_partition_type(self, sector: bytes) -> None:
        """Определяет тип таблицы разделов (MBR или GPT)"""
        # Проверяем сигнатуру MBR
        if sector[510] == 0x55 and sector[511] == 0xAA:
            self.boot_signature = "55 AA"
            
            # Проверяем защитный MBR для GPT
            # Смотрим первый раздел - если тип 0xEE, это GPT
            partition_type = sector[450]  # Тип первого раздела (смещение 0x1C2)
            
            if partition_type == 0xEE:
                self.partition_type = PartitionType.GPT
                print(f"{Colors.GREEN}Обнаружена таблица разделов:{Colors.END} "
                      f"{Colors.BOLD}{Colors.CYAN}GPT (с защитным MBR){Colors.END}")
            else:
                self.partition_type = PartitionType.MBR
                print(f"{Colors.GREEN}Обнаружена таблица разделов:{Colors.END} "
                      f"{Colors.BOLD}{Colors.GREEN}MBR{Colors.END}")
        else:
            # Проверяем сигнатуру GPT
            gpt_signature = sector[0x200:0x208]  # GPT начинается со второго сектора
            if gpt_signature == b'EFI PART':
                self.partition_type = PartitionType.GPT
                print(f"{Colors.GREEN}Обнаружена таблица разделов:{Colors.END} "
                      f"{Colors.BOLD}{Colors.CYAN}GPT{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Не удалось определить тип таблицы разделов{Colors.END}")
    
    def _analyze_mbr(self, sector: bytes, f) -> None:
        """Анализ MBR таблицы разделов"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}[MBR АНАЛИЗ]{Colors.END}")
        
        # Разбор загрузочного кода
        boot_code = sector[:440]
        print(f"{Colors.BLUE}Длина загрузочного кода:{Colors.END} {len(boot_code)} байт")
        
        # Смещения для таблицы разделов MBR
        partition_table_offset = 446
        partition_entry_size = 16
        
        print(f"\n{Colors.BOLD}{Colors.YELLOW}ТАБЛИЦА РАЗДЕЛОВ (4 записи):{Colors.END}")
        print(f"{Colors.CYAN}{'-'*70}{Colors.END}")
        
        # Цвета для разных разделов
        partition_colors = [Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.BLUE]
        
        for i in range(4):
            offset = partition_table_offset + (i * partition_entry_size)
            partition_data = sector[offset:offset + partition_entry_size]
            
            if len(partition_data) < 16:
                continue
                
            # Парсим запись раздела
            status = partition_data[0]
            chs_start = partition_data[1:4]
            type_code = partition_data[4]
            chs_end = partition_data[5:8]
            lba_start = struct.unpack('<I', partition_data[8:12])[0]
            num_sectors = struct.unpack('<I', partition_data[12:16])[0]
            
            if type_code == 0x00 and lba_start == 0:
                continue  # Пустой раздел
                
            # Определяем активность
            is_active = (status == 0x80)
            active_str = f"{Colors.GREEN}✓ АКТИВНЫЙ{Colors.END}" if is_active else "неактивный"
            
            # Определяем тип раздела
            type_str = self._get_partition_description(type_code)
            
            # Рассчитываем размер
            size_bytes = num_sectors * self.sector_size
            size_human = self._bytes_to_human(size_bytes)
            
            # Создаем запись о разделе
            partition = PartitionEntry(
                number=i + 1,
                type=type_str,
                type_code=type_code,
                start_sector=lba_start,
                size_sectors=num_sectors,
                end_sector=lba_start + num_sectors - 1,
                size_bytes=size_bytes,
                size_human=size_human,
                is_active=is_active
            )
            
            self.partitions.append(partition)
            
            # Выводим информацию с цветом
            color = partition_colors[i]
            print(f"{color}{Colors.BOLD}Раздел {i+1}:{Colors.END}")
            print(f"  {Colors.WHITE}Статус:{Colors.END} {active_str}")
            print(f"  {Colors.WHITE}Тип:{Colors.END} 0x{type_code:02X} - {type_str}")
            print(f"  {Colors.WHITE}Начальный LBA:{Colors.END} {lba_start:,}")
            print(f"  {Colors.WHITE}Конечный LBA:{Colors.END} {lba_start + num_sectors - 1:,}")
            print(f"  {Colors.WHITE}Размер:{Colors.END} {num_sectors:,} секторов "
                  f"({size_human})")
            print(f"  {Colors.WHITE}Смещение:{Colors.END} {lba_start * self.sector_size:,} байт")
            print(f"{color}{'-'*40}{Colors.END}")
    
    def _analyze_gpt(self, sector: bytes, f) -> None:
        """Анализ GPT таблицы разделов"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}[GPT АНАЛИЗ]{Colors.END}")
        
        # GPT начинается со второго сектора (LBA 1)
        f.seek(self.sector_size)  # Переходим к GPT заголовку
        gpt_header = f.read(self.sector_size)
        
        if len(gpt_header) < 92:
            print(f"{Colors.RED}Недостаточно данных для GPT заголовка{Colors.END}")
            return
        
        # Парсим GPT заголовок
        signature = gpt_header[0:8].decode('ascii', errors='ignore')
        revision = struct.unpack('<I', gpt_header[8:12])[0]
        header_size = struct.unpack('<I', gpt_header[12:16])[0]
        header_crc = struct.unpack('<I', gpt_header[16:20])[0]
        reserved = struct.unpack('<I', gpt_header[20:24])[0]
        current_lba = struct.unpack('<Q', gpt_header[24:32])[0]
        backup_lba = struct.unpack('<Q', gpt_header[32:40])[0]
        first_usable_lba = struct.unpack('<Q', gpt_header[40:48])[0]
        last_usable_lba = struct.unpack('<Q', gpt_header[48:56])[0]
        disk_guid = binascii.hexlify(gpt_header[56:72]).decode('ascii')
        partition_entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_partition_entries = struct.unpack('<I', gpt_header[80:84])[0]
        partition_entry_size = struct.unpack('<I', gpt_header[84:88])[0]
        partitions_crc = struct.unpack('<I', gpt_header[88:92])[0]
        
        print(f"{Colors.BLUE}GPT Сигнатура:{Colors.END} {signature}")
        print(f"{Colors.BLUE}Disk GUID:{Colors.END} {disk_guid}")
        print(f"{Colors.BLUE}Текущий LBA:{Colors.END} {current_lba}")
        print(f"{Colors.BLUE}Записей разделов:{Colors.END} {num_partition_entries}")
        
        # Читаем таблицу разделов GPT
        partition_table_offset = partition_entries_lba * self.sector_size
        f.seek(partition_table_offset)
        
        print(f"\n{Colors.BOLD}{Colors.YELLOW}ТАБЛИЦА РАЗДЕЛОВ GPT:{Colors.END}")
        print(f"{Colors.CYAN}{'-'*70}{Colors.END}")
        
        partition_num = 1
        for i in range(num_partition_entries):
            entry_data = f.read(partition_entry_size)
            if len(entry_data) < 128:  # Стандартный размер записи GPT - 128 байт
                break
            
            # Первые 16 байт - тип раздела (все нули = пустая запись)
            partition_type_guid = entry_data[0:16]
            if all(b == 0 for b in partition_type_guid):
                continue
            
            # Парсим запись раздела
            partition_guid = entry_data[16:32]
            first_lba = struct.unpack('<Q', entry_data[32:40])[0]
            last_lba = struct.unpack('<Q', entry_data[40:48])[0]
            attributes = struct.unpack('<Q', entry_data[48:56])[0]
            partition_name = entry_data[56:128].decode('utf-16le', errors='ignore').strip('\x00')
            
            if first_lba == 0:
                continue
            
            # Определяем тип раздела по GUID
            type_str = self._get_gpt_partition_type(partition_type_guid)
            
            # Рассчитываем размер
            num_sectors = last_lba - first_lba + 1
            size_bytes = num_sectors * self.sector_size
            size_human = self._bytes_to_human(size_bytes)
            
            # Создаем запись о разделе
            partition = PartitionEntry(
                number=partition_num,
                type=type_str,
                type_code=0,
                start_sector=first_lba,
                size_sectors=num_sectors,
                end_sector=last_lba,
                size_bytes=size_bytes,
                size_human=size_human,
                guid=binascii.hexlify(partition_guid).decode('ascii'),
                name=partition_name,
                attributes=attributes
            )
            
            self.partitions.append(partition)
            
            # Выводим информацию
            color = self._get_partition_color(partition_num)
            print(f"{color}{Colors.BOLD}Раздел {partition_num}: {partition_name}{Colors.END}")
            print(f"  {Colors.WHITE}Тип GUID:{Colors.END} {type_str}")
            print(f"  {Colors.WHITE}Partition GUID:{Colors.END} {partition.guid}")
            print(f"  {Colors.WHITE}Начальный LBA:{Colors.END} {first_lba:,}")
            print(f"  {Colors.WHITE}Конечный LBA:{Colors.END} {last_lba:,}")
            print(f"  {Colors.WHITE}Размер:{Colors.END} {num_sectors:,} секторов ({size_human})")
            print(f"  {Colors.WHITE}Атрибуты:{Colors.END} 0x{attributes:016X}")
            print(f"  {Colors.WHITE}Смещение:{Colors.END} {first_lba * self.sector_size:,} байт")
            print(f"{color}{'-'*40}{Colors.END}")
            
            partition_num += 1
    
    def _find_first_sectors(self) -> None:
        """Находит и показывает первый сектор каждого раздела"""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[ПЕРВЫЕ СЕКТОРЫ РАЗДЕЛОВ]{Colors.END}")
        
        if not self.partitions:
            print(f"{Colors.YELLOW}Разделы не обнаружены{Colors.END}")
            return
        
        for partition in self.partitions:
            color = self._get_partition_color(partition.number)
            
            print(f"\n{color}{Colors.BOLD}Раздел {partition.number}:{Colors.END}")
            print(f"  {Colors.WHITE}Смещение в файле:{Colors.END} "
                  f"{partition.start_sector * self.sector_size:,} байт")
            print(f"  {Colors.WHITE}LBA адрес:{Colors.END} {partition.start_sector:,}")
            print(f"  {Colors.WHITE}Шестнадцатеричный адрес:{Colors.END} "
                  f"0x{partition.start_sector * self.sector_size:08X}")
            
            # Читаем и показываем первые 64 байта первого сектора раздела
            try:
                with open(self.disk_image, 'rb') as f:
                    offset = partition.start_sector * self.sector_size
                    f.seek(offset)
                    first_bytes = f.read(64)
                    
                    if first_bytes:
                        hex_str = binascii.hexlify(first_bytes).decode('ascii')
                        formatted_hex = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                        print(f"  {Colors.WHITE}Первые 64 байта:{Colors.END}")
                        print(f"    {formatted_hex[:47]}...")
            except Exception as e:
                print(f"  {Colors.RED}Ошибка чтения: {str(e)}{Colors.END}")
    
    def _print_colored_hex_dump(self, data: bytes) -> None:
        """Печатает раскрашенный hex дамп первого сектора"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}[HEX ДАМП ПЕРВОГО СЕКТОРА]{Colors.END}")
        print(f"{Colors.YELLOW}Смещение  HEX                                               ASCII{Colors.END}")
        print(f"{Colors.CYAN}{'-'*67}{Colors.END}")
        
        bytes_per_line = 16
        for i in range(0, min(len(data), 256), bytes_per_line):  # Показываем первые 256 байт
            chunk = data[i:i + bytes_per_line]
            
            # HEX часть
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            hex_str = hex_str.ljust(3 * bytes_per_line)
            
            # ASCII часть
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            # Определяем цвет для этой строки
            if i < 440:
                color = Colors.BLUE  # Загрузочный код
                area = "BOOT"
            elif 440 <= i < 446:
                color = Colors.MAGENTA  # Подпись диска
                area = "DSIG"
            elif 446 <= i < 510:
                color = Colors.GREEN  # Таблица разделов
                area = "PART"
            elif i >= 510:
                color = Colors.YELLOW  # Сигнатура
                area = "SIG"
            else:
                color = Colors.WHITE
                area = "DATA"
            
            offset_str = f"0x{i:04X}"
            print(f"{color}{Colors.BOLD}{area:<4}{Colors.END} "
                  f"{Colors.WHITE}{offset_str}{Colors.END}: {hex_str}  |{ascii_str}|")
    
    def _get_partition_description(self, type_code: int) -> str:
        """Возвращает описание типа раздела MBR"""
        partition_types = {
            0x00: "Пустой",
            0x01: "FAT12",
            0x04: "FAT16 <32MB",
            0x05: "Расширенный",
            0x06: "FAT16 >32MB",
            0x07: "NTFS/HPFS/exFAT",
            0x0B: "FAT32 (CHS)",
            0x0C: "FAT32 (LBA)",
            0x0E: "FAT16 (LBA)",
            0x0F: "Расширенный (LBA)",
            0x11: "Скрытый FAT12",
            0x14: "Скрытый FAT16 <32MB",
            0x16: "Скрытый FAT16 >32MB",
            0x1B: "Скрытый FAT32 (CHS)",
            0x1C: "Скрытый FAT32 (LBA)",
            0x1E: "Скрытый FAT16 (LBA)",
            0x82: "Linux Swap",
            0x83: "Linux Native",
            0x85: "Linux Extended",
            0x8E: "Linux LVM",
            0xA5: "FreeBSD",
            0xA6: "OpenBSD",
            0xA8: "macOS Darwin UFS",
            0xA9: "NetBSD",
            0xAB: "macOS Darwin Boot",
            0xAF: "macOS Darwin HFS/HFS+",
            0xB7: "BSDI",
            0xB8: "BSDI Swap",
            0xEE: "GPT защитный MBR",
            0xEF: "EFI System Partition",
            0xFC: "VMWare VMFS",
            0xFD: "Linux RAID",
        }
        return partition_types.get(type_code, f"Неизвестный (0x{type_code:02X})")
    
    def _get_gpt_partition_type(self, guid_bytes: bytes) -> str:
        """Возвращает описание типа раздела GPT по GUID"""
        guid_str = binascii.hexlify(guid_bytes).decode('ascii').upper()
        
        gpt_types = {
            "C12A7328F81F11D2BA4B00A0C93EC93B": "EFI System Partition",
            "E3C9E3160B5C4DB8817DF92DF00215AE": "Microsoft Reserved",
            "EBD0A0A2B9E5443387C068B6B72699C7": "Microsoft Basic Data",
            "5808C8AA7E8F42E085FE4F984F2F9F50": "Linux LVM",
            "0FC63DAF848347728E793D69D8477DE4": "Linux Filesystem",
            "0657FD6DA4AB43C484E50933C84B4F4F": "Linux Swap",
            "8DA63339000011C2950003FF48464D45": "Linux Reserved",
            "83BD6B9D7F418719B69478DDA015F979": "Apple APFS",
            "48465300000011AAAA1100306543ECAC": "Apple HFS+",
            "7C3457EF000011AA8AA3005195CAF3CA": "Apple APFS Container",
        }
        
        return gpt_types.get(guid_str, f"Unknown GUID ({guid_str[:8]}...)")
    
    def _bytes_to_human(self, bytes_size: int) -> str:
        """Конвертирует байты в человекочитаемый формат"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"
    
    def _get_partition_color(self, partition_num: int) -> str:
        """Возвращает цвет для раздела"""
        colors = [Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.BLUE,
                  Colors.MAGENTA, Colors.CYAN, Colors.WHITE]
        return colors[(partition_num - 1) % len(colors)]
    
    def generate_report(self) -> str:
        """Генерирует текстовый отчет"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(f"АНАЛИЗ ДИСКА: {self.disk_image}")
        report_lines.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        report_lines.append(f"Тип таблицы разделов: {self.partition_type.value}")
        report_lines.append(f"Размер диска: {self._bytes_to_human(self.disk_size)}")
        report_lines.append(f"Размер сектора: {self.sector_size} байт")
        report_lines.append("")
        report_lines.append("РАЗДЕЛЫ:")
        report_lines.append("-" * 80)
        
        for partition in self.partitions:
            report_lines.append(f"Раздел {partition.number}:")
            report_lines.append(f"  Тип: {partition.type}")
            report_lines.append(f"  Начальный сектор: {partition.start_sector}")
            report_lines.append(f"  Размер: {partition.size_human}")
            report_lines.append(f"  Смещение в файле: {partition.start_sector * self.sector_size} байт")
            if partition.guid:
                report_lines.append(f"  GUID: {partition.guid}")
            if partition.name:
                report_lines.append(f"  Имя: {partition.name}")
            report_lines.append("")
        
        return '\n'.join(report_lines)

def main():
    parser = argparse.ArgumentParser(description='Анализатор дампа диска Linux')
    parser.add_argument('image', help='Путь к файлу дампа диска')
    parser.add_argument('-s', '--sector-size', type=int, default=512,
                       help='Размер сектора (по умолчанию: 512)')
    parser.add_argument('-o', '--output', help='Файл для сохранения отчета')
    
    args = parser.parse_args()
    
    analyzer = DiskAnalyzer(args.image, args.sector_size)
    
    if analyzer.analyze():
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(analyzer.generate_report())
                print(f"\n{Colors.GREEN}Отчет сохранен в: {args.output}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}Ошибка сохранения отчета: {str(e)}{Colors.END}")
    else:
        print(f"\n{Colors.RED}Анализ завершен с ошибками{Colors.END}")

if __name__ == "__main__":
    import os
    main()