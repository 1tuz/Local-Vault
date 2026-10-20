# Локальная проверка — 2026-10-12

Проверено на macOS ARM64. Все тестовые значения в Rust-тестах вымышленные, хранилища создаются во временных каталогах.

| Проверка | Результат |
| --- | --- |
| `cargo test --target aarch64-apple-darwin` | **3 passed, 0 failed, 0 skipped** |
| `cargo clippy --target aarch64-apple-darwin -- -D warnings` | PASS, предупреждений нет |
| `node --check local_vault/web/app.js` | PASS |
| `cargo audit` | 0 vulnerabilities; 2 allowed warnings (`proc-macro-error` unmaintained; `glib` advisory outside macOS ARM64 dependency graph) |
| `cargo build --release --target aarch64-apple-darwin` | PASS |
| Сборка `.app`, ad-hoc подпись и `codesign --verify` | PASS |
| Запуск установленного `/Users/antony/Desktop/Local Vault.app` | PASS, отдельное macOS-окно Tauri |
| GUI screenshot/AX: создание базы экран | PASS, стили и JS загружаются, исходная верстка видна |
| GUI unlock/CRUD/history/import/export | NOT RUN |
| CLI/MCP, SSH подпись и HTTPS агентский запрос | NOT IMPLEMENTED |
| Совместимость существующего зашифрованного файла | NOT RUN |

GUI-проверка обнаружила ошибку сборки: HTML ссылался на `/static/style.css` и `/static/app.js`, но Tauri раздаёт frontendDist из корня. Исправлены ссылки на `/style.css` и `/app.js`; повторная ARM64-сборка запущена и визуально проверена. Первоначальный экран без стилей был реальным дефектом, приложение повторно собрано после исправления.

Три Rust-теста покрывают создание/шифрование и неверный пароль, CRUD/историю/откат, импорт/экспорт и атомарный отказ на некорректной записи импорта. Полный GUI-цикл и агентские сценарии не доказаны. Код старых Python-тестов удалён при переходе проекта на Rust и в эти три результата не входит.
