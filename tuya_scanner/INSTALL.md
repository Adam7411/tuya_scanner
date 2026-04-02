# Instalacja TinyTuya Scanner Addon

## Metoda 1: Local Addon (najłatwiejsza, bez GitHub)

1. W HA otwórz **Ustawienia → Dodatki → Sklep z dodatkami**
2. Kliknij ⋮ (trzy kropki, prawy górny róg) → **Repozytoria**
3. Zamiast dodawać repo — kliknij ⋮ → **Sprawdź aktualizacje**, potem wróć
4. Otwórz menedżer plików (addon **File Editor** lub **Studio Code Server**)
5. Utwórz folder: `/addons/tuya_scanner/`
6. Wrzuć do niego wszystkie pliki z tego ZIPa:
   ```
   /addons/tuya_scanner/
   ├── config.json
   ├── Dockerfile
   ├── run.sh
   ├── scanner.py
   └── www/
       └── index.html
   ```
7. Wróć do **Sklep z dodatkami** → odśwież stronę
8. Pojawi się sekcja **Lokalne dodatki** → **TinyTuya Scanner**
9. Kliknij **Instaluj** → **Uruchom**
10. Otwórz panel przez **Tuya Scanner** w lewym menu HA ✓

## Metoda 2: Przez Samba / SSH

```bash
# Na serwerze HA (przez SSH addon):
mkdir -p /addons/tuya_scanner/www
# Skopiuj pliki... potem:
ha addons reload
```

## Po instalacji

Panel dostępny pod: `http://TWOJ-HA-IP:7080`
lub przez Ingress (lewe menu HA → Tuya Scanner)

## Konfiguracja (opcjonalna)

W HA → Ustawienia → Dodatki → TinyTuya Scanner → Konfiguracja:

```yaml
scan_interval: 3600   # auto-skan co X sekund (domyślnie 1h)
scan_duration: 18     # czas jednego skanu w sekundach
```

## Wyniki zapisane w:
`/data/devices.json` (wewnątrz kontenera addonu)
