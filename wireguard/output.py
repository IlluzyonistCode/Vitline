'''
Вывод конфигов WireGuard в терминал.
QR-код — для мобильных клиентов (отображается прямо в терминале).
'''
import shutil
import subprocess
import sys


def print_config(config_text, title=None):
    sep = '─' * 56
    if title:
        print(f'\n{sep}')
        print(f'  {title}')
    print(sep)
    print(config_text)
    print(sep)


def print_qr(config_text, title=None):
    '''
    Вывести QR-код конфига в терминал через qrencode.
    Установка: apt install qrencode
    '''
    if title:
        print(f'\n  {title}')

    if not shutil.which('qrencode'):
        print('  [qrencode не установлен: apt install qrencode]')
        print('  Конфиг сохранён в файл, отсканируй вручную.')
        return

    result = subprocess.run(
        ['qrencode', '-t', 'ansiutf8', '-l', 'M'],
        input   = config_text.encode(),
        capture_output = True,
    )
    if result.returncode == 0:
        print(result.stdout.decode())
    else:
        print('  ошибка qrencode:', result.stderr.decode())


def save_config(config_text, path):
    import os
    from pathlib import Path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(config_text)
    p.chmod(0o600)
    print(f'  конфиг сохранён: {p}')
