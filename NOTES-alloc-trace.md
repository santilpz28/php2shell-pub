# PHP2Shell — Bitácora de instrumentación (2026-10-27)

## Objetivo
Escalar el UAF verificado a RCE, determinando el mecanismo real de
liberación y Consumption del slot de `PS(http_session_vars)`.

## Instrumentación
- `patches/apply_trace_patch.py` → `ext/session/session.c`
  - `TRACK_INIT` en `php_session_track_init()`: dirección, flags, nTableSize,
    nNumUsed, arData, pDestructor, sizeof(zend_array).
  - `CLEANUP` en `php_session_rfc1867_cleanup()`: dirección que consume el Request B.
- `patches/apply_alloc_trace_patch.py` → `Zend/zend_alloc.c`
  - `FREE_SMALL ptr=... bin=... size=...`
  - `ALLOC_SMALL bin=... size=... free_slots=... head=...`

Ambos idempotentes. Aplicados ANTES de compilar (`Dockerfile.trace`).

## Resultados

### 1. UAF confirmado con direcciones (2/2 corridas)

```
TRACK_INIT arr=0x79c99ce54310 gc=1          flags=0x8 nTableSize=8 sizeof=56
CLEANUP    arr=0x79c99ce54310 gc=2632270664 flags=0x0 nTableSize=8 nNumUsed=1
```

Segunda corrida (ASLR distinta):
```
TRACK_INIT arr=0x7cd8a2e54310 gc=1          flags=0x8 nTableSize=8 sizeof=56
CLEANUP    arr=0x7cd8a2e54310 gc=2732933960 flags=0x0 nTableSize=8 nNumUsed=1
```

**La dirección `arr` es IDÉNTICA en TRACK_INIT y CLEANUP.** El Request B opera
sobre exactamente el objeto que el Request A liberó. UAF demostrado, no inferido.

Firma del estado liberado:
- `gc.refcount`: 1 → 2632270664 / 2732933960 (basura: un refcount real nunca es eso)
- `flags`: 0x8 → 0x0 (pizados)
- `nNumUsed`: 0 → 1 (bucket reutilizado)
- `nTableSize`: 8 → 8 (sobrevive)
- `pDestructor`: zval_ptr_dtor → zval_ptr_dtor (sobrevive intacto)

### 2. sizeof(zend_array) = 56 bytes → bin 6

`zend_mm_small_size_to_bin()` (Zend/zend_alloc.c), para size <= 64:
`bin = (size - !!size) >> 3` → 56 → (56-1)>>3 = 6.

Rangos: bin 3 = 25-32 B (zend_string del SID), bin 6 = 49-56 B (zend_array),
bin 68 = fuera de rango small (blob de 288 B de los writeups).

**Consecuencia: el spray clásico de 288 bytes vive en el bin 68 y NUNCA puede
reclamar el slot del bin 6. No es timing, no es precisión, no es ASLR: es
CLASE DE TAMAÑO.**

### 3. El pool del bin 6 es contiguo y determinista

Secuencia única de `head` en ALLOC_SMALL bin=6:
```
0x7cd8a2e54038 → 04070 → 040a8 → 040e0 → 04118 → 04150 → 04188 → 041c0
→ 041f8 → 04230 → 04268 → 042a0 → 042d8 → 04310 ← el slot de la zend_array
→ 04348 → 04380 → 043b8 → 043f0 → 04428 → ...
```
Paso constante de **0x38 (56 bytes)**. El slot de la `zend_array` es el
número 14 de la secuencia. La posición dentro del pool es **predecible**.

### 4. El slot se libera y se reasigna (ciclo de vida medido)

```
línea 113      ALLOC_SMALL bin=6 head=0x7cd8a2e54310  ← se asigna (zend_array de sesión)
línea 100295   FREE_SMALL  ptr=0x7cd8a2e54310         ← se libera
línea 100297   ALLOC_SMALL bin=6 head=0x7cd8a2e54310  ← REASIGNADO 2 líneas después
línea 197814   FREE_SMALL  ptr=0x7cd8a2e54310
línea 197816   ALLOC_SMALL bin=6 head=0x7cd8a2e54310
```

El slot **sí** vuelve a la lista de libres y **sí** se reasigna.

### 5. LIFO: 28.4% de aciertos

Sobre 7.463 pares (free→alloc) consecutivos de bin 6:
- **LIFO estricto: 2.123 (28.4%)** — el siguiente alloc de 56 B usa el slot recién liberado.
- **No coincide: 5.340 (71.6%)** — competencia de otros slots/páginas.

Motivo: `heap->free_slot[bin]` es una pila **por página**. Un free en otra
página empuja su propio slot a la cabeza de la lista de esa página.

**Implicación para la escalada:** 28% por intento no es un problema, es una
ventaja: 3-4 intentos dan >70% de éxito acumulado. Explica por qué los
PoC públicos usan spray masivo, y por qué un spray de 56 bytes (no 288)
debería funcionar.

## Estado
- RCE completa: **NO lograda**.
- Pendiente: forzar un allocation de 56 bytes controlado justo tras el OOM
  para que aterrice en el slot, con `pDestructor = zif_system` y el comando
  en un `zend_string` aparte.
