@echo off
REM ==== Остановка Node.js сервера ====

echo Остановка Node.js сервера...

REM Поиск процессов node.exe
for /f "tokens=2" %%i in ('tasklist /fi "imagename eq node.exe" /fo csv ^| find "node.exe"') do (
    echo Найден процесс Node.js с PID: %%i
    taskkill /pid %%i /f
    if %ERRORLEVEL% EQU 0 (
        echo Процесс %%i успешно остановлен
    ) else (
        echo Не удалось остановить процесс %%i
    )
)

REM Альтернативный способ через PowerShell
echo Попытка остановки через PowerShell...
powershell -NoProfile -Command "Get-Process -Name 'node' -ErrorAction SilentlyContinue | Stop-Process -Force"

REM Проверка, что процессы остановлены
tasklist /fi "imagename eq node.exe" /fo csv | find "node.exe" >nul
if %ERRORLEVEL% EQU 0 (
    echo Предупреждение: некоторые процессы Node.js все еще запущены
) else (
    echo Все процессы Node.js остановлены
)

echo Готово.
pause
