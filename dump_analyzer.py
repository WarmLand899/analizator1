#!/usr/bin/env python3
import struct
import sys
import string

# ANSI цвета
COLORS = [
    "\033[91m",  # red
    "\033[92m",  # green
    "\033[93m",  # yellow
    "\033[94m",  # blue
    "\033[95m",  # magenta
    "\033[96m",  # cyan
]
RESET = "\033[0m"


# ---------------------------
#   Загрузка первичного сектора
# ---------------------------
def read_mbr(path):
    with open(path, "rb") as f:
        return f.read(512)


# ---------------------------
#   Парсер MBR-разделов
# ---------------------------
def parse_partition_entry(entry_bytes):
    boot_flag = entry_bytes[0]
    part_type = entry_bytes[4]
    first_sector, total_sectors = struct.unpack("<II", entry_bytes[8:16])

    return {
        "boot_flag": boot_flag,
        "type": part_type,
        "first_sector": first_sector,
        "total_sectors": total_sectors,
    }


def analyze_mbr(mbr):
    sig = struct.unpack("<H", mbr[510:512])[0]
    if sig != 0xAA55:
        print("⚠️ Предупреждение: сигнатура MBR не найдена (0x55AA).")

    partitions = []
    table_off = 446

    for i in range(4):
        entry = mbr[table_off + i * 16 : table_off + (i + 1) * 16]
        partitions.append(parse_partition_entry(entry))

    return partitions


def print_partitions(partitions):
    print("\n📦 Обнаруженные разделы (MBR):\n")
    header = f"{'№':<3} {'Boot':<6} {'Type':<6} {'First sector':<15} {'Total sectors':<15}"
    print(header)
    print("-" * len(header))

    for i, part in enumerate(partitions):
        color = COLORS[i % len(COLORS)]
        print(
            color
            + f"{i+1:<3} "
              f"{hex(part['boot_flag']):<6} "
              f"{hex(part['type']):<6} "
              f"{part['first_sector']:<15} "
              f"{part['total_sectors']:<15}"
            + RESET
        )

# ---------------------------
#   HEX-ДАМП С ASCII
# ---------------------------
def hexdump_with_ascii(data, prefix="BOOT"):
    print("\n[HEX ДАМП ПЕРВОГО СЕКТОРА]")
    print("Смещение        HEX                                              ASCII")
    print("-------------------------------------------------------------------------------")

    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]

        # HEX часть
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(16 * 3 - 1)

        # ASCII часть
        ascii_part = "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in chunk
        )

        print(f"{prefix} 0x{offset:04X}:  {hex_part}  |{ascii_part}|")

#          MAIN
def main():
    if len(sys.argv) != 2:
        print("Использование:\n  python3 mbr_full.py disk.img")
        sys.exit(1)

    path = sys.argv[1]

    mbr = read_mbr(path)

    # Анализ разделов
    partitions = analyze_mbr(mbr)
    print_partitions(partitions)

    # HEX-дамп 
    hexdump_with_ascii(mbr)


if __name__ == "__main__":
    main()


