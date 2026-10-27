# PHP2Shell — Anatomía de CVE-2026-109618 / CVE-2026-109619

### De un use-after-free en la capa de sesiones de PHP a RCE sin autenticación

**Chain-Cortex · JARVIS 🛡️** · 27 de octubre de 2026
**CVSS v4.0:** 9.2 (Crítico) en ambos CVEs
**Estado:** Explotación activa reportada · PoC público disponible

---

> **Este repositorio documenta una investigación de seguridad. Todo el trabajo
> se ha realizado contra contenedores Docker locales en `127.0.0.1`. No se
> ha testeado contra ningún sistema de terceros. El material se publica con
> fines defensivos y de investigación.**

---

## Qué es esto

El 21 de octubre de 2026 el proyecto PHP publicó una release de emergencia
que corrigió **dos** vulnerabilidades críticas en el **núcleo** del lenguaje:

| CVE | Tipo | Efecto |
|---|---|---|
| **CVE-2026-109619** | Use-after-free en `session.upload_progress` | RCE + divulgación de memoria |
| **CVE-2026-109618** | Corrupción de memoria por `longjmp()` en OOM | RCE + divulgación de memoria |

No es un bug de aplicación: es un bug del intérprete. Cualquier endpoint que
acepte un upload multipart es vulnerable aunque tu código sea perfecto. No
requiere autenticación. Y `session.upload_progress.enabled=On` es el default de
fábrica desde PHP 5.

**Este repositorio contiene el artículo técnico completo, el laboratorio
reproducible y las herramientas de detección.**

📄 **[Lee el artículo completo → `BLOG.md`](BLOG.md)** (1.400+ líneas)

---

## El hallazgo que casi nadie menciona

La cadena **no empieza con un use-after-free**. Empieza con un **agotamiento de
memoria**:

```
Request A  multipart con 1.500 uploads anidados vacíos
              → ~536 KB de cuerpo HTTP agotan los 32 MB de heap de PHP
              → zend_bailout() / longjmp() SALTA por encima del cleanup
              → shutdown_memory_manager() libera el heap
              → el worker sobrevive con PS(id) y PS(http_session_vars) colgando

Request B  multipart con PHP_SESSION_UPLOAD_PROGRESS y SIN file part
              → MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
              → php_session_initialize() → zend_hash_del() sobre memoria liberada
              → USE-AFTER-FREE
```

Esto explica por qué el parche oficial sustituye el `longjmp` por un error
blando, y por qué `pm.max_requests=1` rompe la explotabilidad en PHP-FPM.

**Y tiene una consecuencia práctica que casi se menciona:** el ataque **no
tiene ritmo**. La primera descripción del ataque —una pausa de red de más de
un segundo para que expire `session.upload_progress.min_freq`— era
**incorrecta**, y la experimentación de este trabajo lo descartó. Los WAF y
el rate limiting que miran la cadencia de las peticiones **no ven este
ataque**, porque no hay cadencia que mirar.

---

## Estado de la investigación

| Resultado | Estado | Evidencia |
|---|---|---|
| Trigger de OOM con payload pequeño | ✅ Reproducido | 1.500 uploads anidados → 536 KB → `Allowed memory size ... exhausted` |
| Use-after-free en el Request B | ✅ Reproducido | 100 % de las rondas |
| **UAF demostrado con direcciones** | ✅ Reproducido | La instrumentación prueba que el Request B opera sobre **exactamente** la `zend_array` que el Request A liberó |
| Aislamiento del puntero responsable | ✅ Reproducido | Controles A/B: el crash ocurre igual con SID distinto y desaparece sin `PHP_SESSION_UPLOAD_PROGRESS` → es `PS(http_session_vars)` |
| El OOM es necesario y suficiente | ✅ Reproducido | Sin OOM previo: 0/4 crashes. GET normal tras OOM: 4/4 OK |
| Discriminación vulnerable/parcheado | ✅ Reproducido | 8.2.34: OOM 6/6 + UAF 6/6. 8.2.35: OOM 0/6 |
| **Tamaño real del slot liberado** | ✅ Medido | `sizeof(zend_array) = 56 B` → **bin 6** del allocator |
| **Pool del bin 6 predecible** | ✅ Medido | Progresión contigua de paso 0x38; el reparto LIFO acierta el **28,4 %** por intento |
| Efecto de OPcache sobre la expresión del UAF | ✅ Aislado | Mismo binario: con OPcache 0/6, sin OPcache 6/6 |
| Exfiltración de memoria controlada | ⚠️ No lograda | El puntero se lee, pero el `ZSTR_LEN` queda en 32 |
| RCE completa | ❌ No lograda | Bloqueante: reclamar el slot con una `zend_array` forjada de 56 B |

> **Honestidad por delante de la marca:** lo que no se reproduce aquí no se
> afirma. El artículo documenta la diferencia con precisión, en lugar de
> presentar como verificado lo que procede de la literatura pública.

### Por qué los PoC públicos fallan

Un hallazgo que se aparta de la literatura y que explica por qué el spray
"clásico" de 288 bytes **no puede funcionar** en PHP 8.2:

| Objeto | Tamaño | Bin del allocator |
|---|---|---|
| `zend_string` del SID | 32 B | 3 |
| **`zend_array` de sesión (el slot a reclamar)** | **56 B** | **6** |
| Blob "clásico" de los writeups | 288 B | **68** |

En Zend MM los allocations pequeños se agrupan en bins, y
`zend_mm_small_size_to_bin()` da `bin = (size - !!size) >> 3` para `size <= 64`.
**Dos bins distintos nunca comparten bloques.** El spray de 288 bytes vive en
el bin 68 y jamás puede tocar el slot del bin 6. No es un problema de timing,
ni de precisión, ni de ASLR: es un problema de **clase de tamaño**.

---

## Herramientas

| Fichero | Qué hace |
|---|---|
| `check_exposure.sh` | Sonda de exposición de una pasada. `exit 1` = vulnerable, `exit 0` = parcheado |
| `behavioural_diff.py` | Test diferencial vulnerable/parcheado con controles A/B |
| `php2shell_leak.py` | Detector del UAF con controles negativos |
| `php2shell_rce.py` | Andamiaje de la escalada: monta el escenario real y recoge la traza |
| `patches/` | Parches idempotentes que instrumentan el propio PHP (sesión + allocator) |
| `web/` | Endpoints del laboratorio |

### Inicio rápido

```bash
# Levantar vulnerable (8080) + parcheado (8081)
bash lab.sh

# Comprobar exposición
./check_exposure.sh http://127.0.0.1:8080   # exit 1 → vulnerable
./check_exposure.sh http://127.0.0.1:8081   # exit 0 → parcheado

# Test diferencial
python3 behavioural_diff.py --url http://127.0.0.1:8080
```

### Target instrumentado

El target que registra qué ocurre dentro del allocator:

```bash
docker build -f Dockerfile.trace -t php2shell-trace:8.2.34 .
docker run -d --name php2shell-trace -p 127.0.0.1:8084:80 \
  -v "$PWD/web:/var/www/html" --entrypoint /usr/sbin/apache2 \
  php2shell-trace:8.2.34 -D FOREGROUND

python3 php2shell_rce.py probe --port 8084 --records 1500

docker exec php2shell-trace cat /tmp/php2shell_trace.log   # sesión
docker exec php2shell-trace cat /tmp/php2shell_alloc.log   # allocator
```

Los parches se aplican **antes de compilar** y son idempotentes: el target es
reproducible desde cero. Detalles en [`NOTES-alloc-trace.md`](NOTES-alloc-trace.md).

---

## Remedios

**El parche es la única respuesta completa.** Las mitigaciones por INI son
parciales por diseño.

| Versión parcheada | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 |
|---|---|
| **PHP 7.4** | **EOL — sin parche. Vulnerable para siempre.** |

Mitigaciones parciales (defensa en capas, no sustituyen al parche):

```ini
; Corta el trigger del OOM (no el UAF)
max_multipart_body_parts = 2000
max_file_uploads = 100

; Reduce el impacto del UAF
pm.max_requests = 1        ; rompe el requisito de "mismo worker" (solo FPM)
```

> ⚠️ **No desactives OPcache en producción.** Con OPcache el UAF puede
> manifestarse de forma silenciosa en vez de con SIGSEGV. Eso es **peor**: no
> delata el fallo. Solo se desactiva en el laboratorio, por reproducibilidad.

---

## Sobre la reproducción

- Todo el trabajo se ha hecho contra **contenedores Docker locales**.
- Los targets usan PHP 8.2.34 (vulnerable) y 8.2.35 (parcheado).
- El target instrumentado se compila desde el código fuente de PHP con
  `Dockerfile.trace`; tarda ~20 min (el build **no** usa `-j` a propósito: con
  `-j` el enlazador de `libphp.so` consume >2 GB y el build muere con OOM).
- La CLI de `apache2` corre con ASLR **activo** en los contenedores actuales:
  `setarch -R` requiere privilegios que Docker no concede por defecto. Las
  direcciones medidas son relativas a la base de cada ejecución.

---

## Licencia

MIT · © 2026 Chain-Cortex

El artículo de comunicación y venta de servicios está en
[`COMMUNICATION.md`](COMMUNICATION.md).
