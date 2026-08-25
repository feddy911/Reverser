import os
os.environ['PATH'] = r"D:\Hryusha\Tools\radare2\bin" + ";" + os.environ['PATH']

import r2pipe
import json
import os

def decompile_function(binary_path: str, function_name: str = "main") -> dict:
    """
    Открывает бинарник в Radare2, находит функцию и декомпилирует её через pdc
    """
    try:
        # Открываем бинарник
        r2 = r2pipe.open(binary_path, flags=['-e', 'scr.color=0'])

        # Выполняем полный анализ
        print("[*] Анализируем бинарник...")
        r2.cmd('aaa')

        # Получаем список функций через afl (текстовый формат)
        afl_output = r2.cmd('afl')
        functions = []

        for line in afl_output.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.strip().split()
            if len(parts) >= 4:
                try:
                    addr = int(parts[0], 16)
                    refs = int(parts[1])
                    size = int(parts[2])
                    name = ' '.join(parts[3:])

                    functions.append({
                        'offset': addr,
                        'refs': refs,
                        'size': size,
                        'name': name
                    })
                except ValueError:
                    continue

        print(f"[*] Найдено функций: {len(functions)}")

        # Ищем нужную функцию
        target_func = None

        for func in functions:
            name = func['name']
            addr = func['offset']

            if addr == 0:
                continue

            if function_name.lower() in name.lower() or name.lower().endswith(function_name.lower()):
                target_func = func
                break

        # Если не нашли, ищем main или entry
        if not target_func:
            for func in functions:
                name = func['name']
                addr = func['offset']
                if addr != 0 and ('main' in name.lower() or 'entry' in name.lower()):
                    target_func = func
                    break

        # Если всё ещё не нашли, берём первую ненулевую функцию
        if not target_func:
            for func in functions:
                if func['offset'] != 0:
                    target_func = func
                    break

        if not target_func:
            return {"error": "No valid functions found"}

        func_name = target_func['name']
        func_addr = target_func['offset']
        func_size = target_func['size']

        print(f"[*] Декомпилируем: {func_name} @ {hex(func_addr)} (size: {func_size})")

        # Переходим к функции
        r2.cmd(f's {hex(func_addr)}')

        # Используем только pdc (встроенный декомпилятор)
        print("[*] Используем pdc (встроенный декомпилятор)...")
        decompiled = r2.cmd('pdc')

        if not decompiled or not decompiled.strip():
            # Если pdc не сработал, используем дизассемблер
            print("[!] pdc не сработал, используем pdf (дизассемблер)")
            decompiled = r2.cmd(f'pdf @{hex(func_addr)}')

        # Получаем дополнительную информацию
        try:
            func_info = r2.cmd(f'afi @ {hex(func_addr)}')
        except:
            func_info = ""

        r2.quit()

        return {
            "function_name": func_name,
            "address": hex(func_addr),
            "size": func_size,
            "decompiled_code": decompiled,
            "function_info": func_info,
            "method": "pdc (встроенный)"
        }

    except Exception as e:
        return {"error": str(e)}


# Тест
if __name__ == "__main__":
    test_binary = "test.exe"
    print(f"=== Декомпиляция {test_binary} ===\n")
    result = decompile_function(test_binary, "main")
    print("\n=== РЕЗУЛЬТАТ ===")
    print(json.dumps(result, indent=2, ensure_ascii=False))