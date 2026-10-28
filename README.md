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

## ⚠️ Disclaimer de estado — leer antes de usar este repositorio

Este disclaimer se añadió **al cierre del trabajo** para que nadie confunda
"código publicado" con "cadena de explotación verificada". No implica que el
resto del material haya sido modificado: el artículo, los PoC y los scripts se
mantienen tal cual.

> **Actualización posterior:** el artículo **sí** ha recibido una corrección
> técnica posterior, documentada en §10.11-bis: se demostró que `zif_system`
> **no** es un gadget válido, porque su firma real
> (`void (zend_execute_data *, zval *)`) es incompatible con `dtor_func_t`
> (`void (*)(zval *)`). Esa corrección afecta a la premisa del RCE, no al
> mecanismo del UAF, que sigue verificado.

### Qué está verificado de extremo a extremo

| Artefacto | Estado |
|---|---|
| Análisis del código fuente de PHP 8.2.34 (`ext/session/session.c`) | ✅ Verificado directamente |
| Lectura y contraste del parche oficial `31c0ea7d7ff` | ✅ Verificado directamente |
| Layout de `zend_internal_function` (size=136, `handler` en offset 72) | ✅ Verificado con programa `offsetof` contra `Zend/zend_compile.h` |
| Test diferencial vulnerable/parcheado (`behavioural_diff.py`) | ✅ Ejecutado contra 8.2.34 y 8.2.35 reales |
| Backport del commit de parche sobre 8.2.34 (sin cambio de versión) | ✅ Compilado y ejecutado: **6/6 UAF en el sin parchear, 0/6 en el parcheado**, con `php -v` idéntico |
| Mecanismo del UAF con direcciones reales y tamaño del slot | ✅ Medido en el binario instrumentado |
| Tamaño del `zend_array` liberado (56 B, bin 6) y posición en el pool (elemento 14, paso 0x38) | ✅ Medido |
| Reutilización del slot liberado por el siguiente allocation de 56 B | ⚠️ 28,4 % por intento (LIFO, por páginas) |
| Mapping contra el advisory oficial `GHSA-6wmf-4rv5-p3rp` (producer/consumer) | ✅ Contrastado punto por punto |
| Componentes del PoC de RCE (spray, timing, forja de la struct, extracción de offsets) | ✅ Implementados y verificados por separado |

### Qué **no** está verificado

- **La cadena de RCE completa no se reprodujo de principio a fin.** La imagen
  `php2shell-rce:8.2.34` compila y sirve tráfico, pero el tránsito de la
  petición que encadena OOM → UAF → forja de `zend_array` → llamada a
  `system()` no llegó a ejecutar código de forma observable en este entorno.

- **El bloqueo está identificado y medido, no es una incógnita.** El volcado
  crudo de memoria del array colgante (§10.11-ter) muestra que sus últimos
  24 bytes fueron sobrescritos por el allocator: `pDestructor` vale
  `arr + 0x50` y `arData` vale `arr + 0x30` — **basura auto-referencial, no
  punteros a función**. Una versión anterior de este README afirmaba que
  `pDestructor` conservaba `zval_ptr_dtor`; era una inferencia y la
  medición la refutó. Los requisitos que faltan son (a°) que un allocation de
  56 B aterrice exactamente en el slot liberado — alcanzable con spray, no con
  control exacto — y (b°) que ese allocation **reconstruya** a la vez el
  `pDestructor` del offset `0x30` y una `arData` válida del offset `0x10`
  con su tabla de buckets y un bucket `IS_STRING`. Detalle en **§10.11-bis**
  y **§10.11-ter** del artículo, y en los logs crudos de `evidence/`.

- **Por tanto, `php2shell_rce.py` y `php2shell_rce_exploit.py` son andamiaje
  de investigación, no exploits funcionales.** No los trates como
  weaponizables. Su valor es otro: ejecutan el escenario real y **reportan el
  estado del gadget en cada intento**, de modo que el progreso es medible y
  otro investigador con un entorno más adecuado puede continuar desde ahí.

- **El spray clásico de 288 bytes de los writeups públicos no sirve** para este
  mecanismo (§10.6): no se modeló un spray de 56 bytes con la precisión de
  puntero necesaria. No se construyeron allocations con contenido elegido por
  el atacante.

- **Las cifras del spray (149 × 288 bytes) proceden del análisis público de
  Akamai**, no de una calibración propia. El layout de la estructura forjada sí
  se contrastó de forma independiente contra el código fuente de PHP.

- **El detector funcional (`behavioural_diff.py`) sí es la pieza operativa
  válida**: distingue vulnerable de parcheado por comportamiento observable,
  sin offsets, sin ASLR y sin ejecutar exploits. Es la recomendada para
  inventariar exposición en flota.

### Advertencia operativa

- **No ejecutes esto fuera de un entorno aislado.** Los contenedores están
  deliberadamente configurados con ASLR desactivado, `mpm_prefork` y PHP 8.2.34
  sin parche. Eso los hace vulnerables **a propósito**.
- **Audita cualquier PoC de terceros antes de ejecutarlo.** Se documenta
  (JFrog) que algunos repositorios públicos para estas CVEs distribuyen cargas
  maliciosas falsas — en algún caso, un script que solo modificaba el fondo de
  pantalla del sistema.
- **El blog distingue en cada sección si una afirmación es verificación propia
  o análisis público.** Si vas a citarlo comercialmente, mantén esa distinción:
  es lo que sostiene la credibilidad del trabajo.

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

> **Validado contra el advisory oficial** (`GHSA-6wmf-4rv5-p3rp`, 21-oct-2026).
> PHP describe el fallo en abstracto —«*global state retained by a worker but
> pointing to memory owned by one request*», «*a fatal error, including one
> caused by memory exhaustion*»— y propone un modelo de **productor + consumidor**
> en requests distintos del mismo worker. La rama `session.upload_progress` que
> se mide aquí es **una** concreción de ese modelo; el mapping punto por punto
> está en [`BLOG.md` §10.12](BLOG.md).

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
| `verify_backport.py` | Verifica si un PHP lleva el parche aplicado **independientemente de su número de versión** (por código y/o comportamiento) |
| `php2shell_leak.py` | Detector del UAF con controles negativos |
| `php2shell_rce.py` | Andamiaje de la escalada: monta el escenario real y recoge la traza. **⚠️ En desarrollo — la cadena completa de RCE no se reprodujo de extremo a extremo (ver disclaimer arriba).** |
| `php2shell_rce_exploit.py` | Ejecuta el escenario real y reporta el estado del gadget por intento. **⚠️ No produce ejecución de código (ver disclaimer arriba).** |
| `patches/` | Parches idempotentes que instrumentan el propio PHP (sesión + allocator) |
| `patches/apply_backport.sh` | Aplica el parche oficial sobre 8.2.34 **sin cambiar de versión** y recompila |
| `patches/php-8.2.34-backport-bailout.patch` | El parche ya resuelto, listo para `git apply` sobre el tag `php-8.2.34` |
| `patches/RESOLUTION-NOTES.md` | Detalle de los 3 conflictos del backport y de por qué se resolvieron así |
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

### Third target: parcheado SIN cambiar de versión

Los dos targets anteriores se construyen asi:

| Target | Versión | Como se obtiene |
|---|---|---|
| `php2shell-vuln:8.2.34` | 8.2.34 | `docker build -f Dockerfile -t php2shell-vuln:8.2.34 .` |
| `php2shell-patched:8.2.35` | 8.2.35 | `docker build -f Dockerfile.patched -t php2shell-patched:8.2.35 .` |
| `php2shell-backport:8.2.34` | **8.2.34** | `docker build -f Dockerfile.backport -t php2shell-backport:8.2.34 .` |

El tercero es el interesante: **mismo número de versión que el vulnerable,
mismas extensiones, mismo ABI. Solo cambia el código.** El parche oficial
("Avoid state corruption via bailout", `31c0ea7d7ff`) se aplica sobre el
árbol de fuentes de 8.2.34 y se recompila.

```bash
docker compose up -d
python3 behavioural_diff.py 127.0.0.1 8080 "8.2.34 SIN parche"
python3 behavioural_diff.py 127.0.0.1 8081 "8.2.35 oficial"
python3 behavioural_diff.py 127.0.0.1 8082 "8.2.34 + backport"

# Verificar la huella del parche sin mirar el número de versión
python3 verify_backport.py --container php2shell-backport
```

Resultado medido (6 rondas por target, evidencia en `evidence/backport/`):

| Target | Versión `php -v` | OOM | UAF consumido | Veredicto |
|---|---|---|---|---|
| `:8080` | 8.2.34 | **6/6** | **6/6** (3 SIGSEGV + 3 stale SID) | VULNERABLE |
| `:8081` | 8.2.35 | 0/6 | 0/6 | PARCHEADO |
| `:8082` | **8.2.34** | 0/6 | 0/6 | **PARCHEADO** |

El backport produce el mismo comportamiento que el 8.2.35 oficial sin tocar
el número de versión. Detalle de los conflictos y del procedimiento, en
[`patches/RESOLUTION-NOTES.md`](patches/RESOLUTION-NOTES.md).

---

## Remedios

**El parche es la única respuesta completa.** Las mitigaciones por INI son
parciales por diseño.

| Versión parcheada | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 |
|---|---|
| **PHP 7.4 / 8.0 / 8.1** | Fuera de soporte del proyecto PHP, pero **PHP ha publicado backports mínimos de código fuente**. Actualiza al paquete de tu distro o a un backport, no a una versión EOL tal cual. |

### Y si no puedes actualizar de versión

Actualizar PHP es lo correcto, pero no siempre es posible: extensiones PECL
compiladas contra una versión concreta, dependencias de plataforma, o
certificaciones que fijan la pila. En ese caso existe una cuarta vía:
**parchear el código conservando la versión.**

El parche oficial es un *commit* (`31c0ea7d7ff`, "Avoid state corruption via
bailout"), no un binario. Aplicado sobre 8.2.34:

- El commit **upstream** de la rama 8.2 toca 423 ficheros y reescribe el
  allocator de Zend MM: no es cherry-pickeable sobre 8.2.34 (conflictos en
  el núcleo del motor).
- Las ramas **EOL** (7.4, 8.0, 8.1) llevan **el mismo fix reducido a su forma
  mínima** (23 ficheros). Ese sí aplica sobre 8.2.34 con solo 3 conflictos en
  código, todos triviales.

```bash
docker build -f Dockerfile.backport -t php2shell-backport:8.2.34 .
python3 verify_backport.py --container php2shell-backport   # → PATCHED
```

El resultado: **mismo `php -v`, mismas extensiones, mismo ABI.** Es la
diferencia entre *parchear* y *reescribir*.

> ⚠️ **Limitación honesta.** El backport de la rama EOL es una **mitigación
> mínima**, no el fix completo de upstream. Desactiva el callback de
> `session.upload_progress` de forma permanente: eso corta la cadena de
> ataque, pero también **desactiva una funcionalidad legítima** (el tracking
> de progreso de uploads). Si tu aplicación lo usa, eso es un cambio de
> comportamiento observable. Procedimiento y detalle de los conflictos:
> [`patches/RESOLUTION-NOTES.md`](patches/RESOLUTION-NOTES.md).

> ⚠️ **Corrección (27-oct-2026, 23:20):** versiones anteriores de este README
> afirmaban que PHP 7.4 quedaría «vulnerable para siempre». **Es incorrecto**:
> el proyecto PHP publicó backports mínimos para 7.4, 8.0 y 8.1. Lo que sí
> es cierto es que esas ramas no reciben el ciclo regular de desarrollo, así
> que la actualización depende de tu distro o de aplicar el backport a mano.
> Verificado contra el advisory de NCSC-NL y el advisory oficial
> `GHSA-6wmf-4rv5-p3rp`.

Mitigaciones parciales (defensa en capas, no sustituyen al parche):

```ini
; Recomendada por el propio proyecto PHP (advisory del 23-oct-2026)
session.upload_progress.enabled = 0

; Corta el trigger del OOM (no el UAF)
max_multipart_body_parts = 2000
max_file_uploads = 100

; Reduce el impacto del UAF
pm.max_requests = 1        ; rompe el requisito de "mismo worker" (solo FPM)
```

> **CVE-2026-115560.** El 23 de octubre, PHP publicó un aviso informativo
> sobre un vector de RCE residual ( improbable en la práctica: requiere
> `session.serialize_handler` = `php_binary`/`php_serialize` y luego cambiarlo
> a `php` en runtime con `ini_set()` antes de `session_start()`).
> La mitigación recomendada por el proyecto es
> `session.upload_progress.enabled=0` hasta la siguiente release regular.
> **El advisory oficial `GHSA-6wmf-4rv5-p3rp` ya listaba esa mitigación
> desde el 21 de octubre.**

> ⚠️ **No desactives OPcache en producción.** Con OPcache el UAF puede
> manifestarse de forma silenciosa en vez de con SIGSEGV. Eso es **peor**: no
> delata el fallo. Solo se desactiva en el laboratorio, por reproducibilidad.

---

## Sobre la reproducción

- Todo el trabajo se ha hecho contra **contenedores Docker locales**.
- Los targets usan PHP 8.2.34 (vulnerable), 8.2.35 (parcheado por upgrade) y
  8.2.34 + backport del commit de parche (parcheado sin upgrade).
- El target instrumentado se compila desde el código fuente de PHP con
  `Dockerfile.trace`; tarda ~20 min (el build **no** usa `-j` a propósito: con
  `-j` el enlazador de `libphp.so` consume >2 GB y el build muere con OOM).
- La CLI de `apache2` corre con ASLR **activo** en los contenedores actuales:
  `setarch -R` requiere privilegios que Docker no concede por defecto. Las
  direcciones medidas son relativas a la base de cada ejecución.

---

## Other languages

**English edition:** https://github.com/santilpz28/php2shell-pub-en
(`BLOG.en.md`, `README.en.md`, `PUBLICATION.en.md`, `NOTES-alloc-trace.en.md`)

## Publicación

Los textos listos para publicar (post de LinkedIn, hilo de Twitter/X, newsletter)
y la descripción/topics del repo están en
[`PUBLICATION.md`](PUBLICATION.md).

## Citar este trabajo

```bibtex
@misc{php2shell_chaincortex_2026,
  title  = {PHP2Shell — Anatomía de CVE-2026-109618 y CVE-2026-109619},
  author = {Santiago L{\'o}pez (Chain-Cortex)},
  year   = {2026},
  url    = {https://github.com/santilpz28/php2shell-pub},
  note   = {Investigación de seguridad. Uso defensivo.}
}
```

## Licencia

MIT · © 2026 Chain-Cortex

El artículo de comunicación y venta de servicios está en
[`COMMUNICATION.md`](COMMUNICATION.md).
