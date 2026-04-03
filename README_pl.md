
# TinyTuya Scanner (Dodatek do Home Assistant)

TinyTuya Scanner to dodatek do Home Assistant, który udostępnia przejrzysty interfejs webowy do wykrywania urządzeń Tuya w Twojej sieci lokalnej i wzbogacania ich o metadane z chmury Tuya (w tym Klucze Lokalne) w jednym praktycznym przepływie pracy.

Ten projekt jest **interfejsem użytkownika** dla ekosystemu TinyTuya.  
Nie zastępuje on podstawowej funkcjonalności TinyTuya.

---

## Co robi ten dodatek

Dodatek został zaprojektowany w oparciu o 3-etapowy przepływ operacyjny:

1. **Skanowanie sieci lokalnej** w poszukiwaniu urządzeń Tuya (IP, ID urządzenia, wersja protokołu, MAC – jeśli dostępny)
2. **Pobieranie metadanych i kluczy z chmury** przez poświadczenia API Tuya
3. **Scalenie wszystkiego w jedną tabelę** do celów diagnostycznych i przygotowania automatyzacji

---

## Funkcje

- Lokalne wykrywanie urządzeń Tuya (skanowanie UDP/TCP)
- Opcjonalne **wymuszone skanowanie podsieci (CIDR)** dla trudniejszych konfiguracji sieci
- Pobieranie kluczy z chmury Tuya (Access ID / Secret)
- Ujednolicona tabela urządzeń z:
  - Nazwą
  - IP
  - MAC
  - Wersją
  - ID urządzenia
  - ID produktu
  - Kluczem lokalnym
  - Statusem (`online`, `offline`, `cloud-only`)
- Podsumowanie jakości danych:
  - Liczba urządzeń online
  - Urządzenia z kluczem lokalnym
  - Urządzenia z adresem MAC
  - Urządzenia z ID produktu
- Diagnostyka DPS dla poszczególnych urządzeń (podgląd surowego JSON)
- Pomocnicy do kopiowania/eksportu na potrzeby integracji i debugowania
- Wielojęzyczny interfejs (EN / PL / DE / FR)

<img width="1920" height="3873" alt="screenshot_2-04-2026_14-53-02" src="https://github.com/user-attachments/assets/c8939a30-3f8e-4ffd-92f5-f7ef1241b378" />

---

## Instalacja

### 1) Dodanie repozytorium do Home Assistant

1. Otwórz Home Assistant
2. Przejdź do **Ustawienia -> Dodatki -> Sklep z dodatkami**
3. Kliknij ikonę menu (w prawym górnym rogu, trzy kropki) -> **Repozytoria**
4. Dodaj adres URL swojego repozytorium:
