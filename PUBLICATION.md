# PHP2Shell — Notas de publicación

**Repositorio:** https://github.com/santilpz28/php2shell-pub
**Artículo:** [`BLOG.md`](BLOG.md) · **Bitácora:** [`NOTES-alloc-trace.md`](NOTES-alloc-trace.md)

---

## Descripción del repo (copiar en GitHub → Settings → General)

```
Anatomy of CVE-2026-109618 / CVE-2026-109619: a use-after-free in PHP's
session layer (CVSS 9.2). Chain-Cortex research with a reproducible Docker
lab, an exposure detector, and the real mechanism verified against the
PHP 8.2.34 source.
```

## Topics (GitHub → Settings → Topics)

```
php security cve rce use-after-free vulnerability-research heap chain-cortex
```

---

## Social

### LinkedIn (post largo)

**Título:** PHP2Shell: dos CVEs de 9.2 en el núcleo de PHP. Tu aplicación puede ser perfecta y seguir siendo vulnerable.

**Cuerpo:**

> El 21 de octubre, el proyecto PHP publicó una release de emergencia que corrigió dos vulnerabilidades críticas en el **núcleo** del lenguaje:
>
> | CVE | Efecto |
> |---|---|
> | **CVE-2026-109619** | RCE + divulgación de memoria (use-after-free en `session.upload_progress`) |
> | **CVE-2026-109618** | RCE + divulgación de memoria (corrupción por OOM) |
>
> CVSS v4.0: **9.2** en ambos.
>
> Lo que lo hace que no sea "un bug más":
>
> **1. No es un bug de aplicación.** Es del intérprete. Cualquier endpoint que acepte un upload multipart es vulnerable, aunque tu código sea impecable.
>
> **2. Sin autenticación.** No hay login que saltar.
>
> **3. Configuración por defecto vulnerable.** `session.upload_progress.enabled=On` es el default de fábrica desde PHP 5.
>
> **4. PHP 7.4, 8.0 y 8.1 están fuera del ciclo regular.** PHP publicó backports mínimos de código fuente, pero no el ciclo regular de releases: la actualización depende de tu distro.
>
> CISA, Cisco, Akamai, Vercel, Laravel, Autodesk, IC3 y CERT-EU publicaron alertas el mismo día. Hay indications de explotación activa.
>
> **Versiones parcheadas:** 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12
>
> ---
>
> Lo que nos ocupó: **el mecanismo real no es el que describe la mayoría de la literatura.**
>
> Montamos un laboratorio con el vulnerable y el parcheado, instrumentamos el propio PHP y medimos.
>
> **El hallazgo:** la cadena no empieza con un use-after-free. Empieza con un **agotamiento de memoria**.
>
> ```
> Request A → 1.500 uploads anidados vacíos → ~536 KB de cuerpo HTTP
>           → agota los 32 MB de heap de PHP
>           → zend_bailout() / longjmp() SALTA por encima del cleanup
>           → el heap se libera, el worker sobrevive con punteros colgando
>
> Request B → multipart con PHP_SESSION_UPLOAD_PROGRESS y SIN file part
>           → MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
>           → php_session_initialize() → zend_hash_del() sobre memoria liberada
>           → USE-AFTER-FREE
> ```
>
> Tres consecuencias que no aparecen en los writeups:
>
> **① El ataque no tiene ritmo.** La primera descripción —"una pausa de red de más de un segundo para que expire `session.upload_progress.min_freq`"— era **incorrecta**, y la experimentación lo descartó. La cadena es determinista. **Los WAF y el rate limiting que miran la cadencia no ven este ataque**, porque no hay cadencia que mirar. Uno que limite el *tamaño del body* tampoco: ~536 KB bastan. Uno que limite el **número de ficheros anidados**, sí.
>
> **② Instrumentar el binario es lo que convierte la hipótesis en prueba.** Metimos dos trazas en `ext/session/session.c` y el Request B resultó operar sobre **exactamente** la `zend_array` que el Request A liberó — misma dirección, con el refcount y los flags ya corruptos. No inferido: medido.
>
> **③ Por qué fallan los PoC públicos.** `sizeof(zend_array) = 56 bytes` → **bin 6** del allocator de Zend MM. El blob de 288 bytes que usan los writeups vive en el **bin 68**. Dos bins nunca comparten bloques. No es timing, no es precisión, no es ASLR: es **clase de tamaño**. Instrumentando el allocator vimos que el pool del bin 6 es una progresión contigua de paso 0x38 — el slot es predecible — y que el reparto LIFO acierta el **28,4 %** por intento.
>
> Y esto último valida el trabajo entero: el advisory oficial de PHP (`GHSA-6wmf-4rv5-p3rp`) describe exactamente este modelo abstracto —*"global state retained by a worker but pointing to memory owned by one request"*, *"a fatal error, including one caused by memory exhaustion"*, productor y consumidor en requests distintos del mismo worker. La rama de sesión que medimos es una concreción de ese modelo. El vendor y el laboratorio llegaron al mismo sitio por caminos distintos.
>
> **Lo que NO se logró, y lo decimos:** la RCE completa. No logramos reclamar el slot liberado con una `zend_array` forjada. Lo que sí quedó es que el bloqueo restante es **control del allocator**, no timing — y por qué el spray clásico no puede funcionar. Está todo documentado, con la evidencia.
>
> Publicamos el laboratorio completo: Docker reproducible, los dos parches idempotentes que instrumentan el propio PHP, un detector de exposición que discrimina vulnerable de parcheado **sin ejecutar exploits ni necesitar offsets**, y el artículo técnico con los controles A/B y el desensamblado.
>
> → https://github.com/santilpz28/php2shell-pub
>
> Si tu flota usa PHP 7.4/8.0/8.1, o no puedes actualizar en 48 h, hablemos: montamos un inventario de exposición con ese test diferencial. →
>
> #cybersecurity #php #securityresearch #vulnerability #CVE #RCE #pentesting #appsec #infosec #chaincortex

---

### Twitter / X (hilo)

```
1/ PHP2Shell: dos CVEs de 9.2 en el núcleo de PHP (CVE-2026-109618 / -109619).
RCE sin autenticación en cualquier endpoint que acepte uploads multipart.
Tu código puede ser perfecto y seguir siendo vulnerable. 🧵

2/ Lo interesante: el mecanismo real NO es el que describe la mayoría de la
literatura. La cadena no empieza con un UAF, empieza con un OOM.

Request A → 1.500 uploads anidados vacíos → ~536 KB → agota 32 MB de heap PHP
→ zend_bailout() salta el cleanup → heap liberado, worker sigue vivo

3/ Request B → multipart con PHP_SESSION_UPLOAD_PROGRESS y SIN file part
→ MULTIPART_EVENT_END → php_session_rfc1867_cleanup() → php_session_initialize()
→ zend_hash_del() sobre memoria ya liberada → USE-AFTER-FREE

4/ Consecuencia práctica: el ataque NO tiene ritmo. Es determinista.
Los WAF que miran la cadencia de las peticiones no lo ven.
Y uno que limite el tamaño del body tampoco: 536 KB bastan.
Uno que limite el NÚMERO de ficheros anidados, sí.

5/ Instrumentamos el propio PHP (parches idempotentes sobre session.c).
El Request B opera sobre EXACTAMENTE la zend_array que el Request A liberó.
Misma dirección, refcount y flags ya corruptos. No inferido: medido.

6/ Por qué fallan los PoC públicos: sizeof(zend_array) = 56 B → bin 6 del
allocator. El blob de 288 B de los writeups vive en el bin 68. Dos bins nunca
comparten bloques. No es timing, ni precisión, ni ASLR: es clase de tamaño.

7/ Instrumentando el allocator: el pool del bin 6 es una progresión contigua
de paso 0x38 → el slot es predecible. Reparto LIFO: 28,4 % de acierto por
intento. El bloqueo restante es control del allocator, no timing.

8/ Lo que NO logramos: la RCE completa. No pudimos reclamar el slot con una
zend_array forjada. Está documentado como tal, con la evidencia.

9/ El vendor y el laboratorio llegamos al mismo sitio por caminos distintos:
el advisory oficial (GHSA-6wmf-4rv5-p3rp) describe exactamente este modelo
abstracto — productor y consumidor, requests distintos, mismo worker.

10/ Laboratorio completo: Docker reproducible, detector de exposición que
discrimina vulnerable de parcheado SIN ejecutar exploits ni necesitar offsets.

https://github.com/santilpz28/php2shell-pub
```

---

## Newsletter (opción B)

**Asunto:** PHP2Shell — auditoría urgente de exposición en PHP

**Cuerpo:**

> El 21 de octubre de 2026 se publicó una release de emergencia de PHP que corrige dos vulnerabilidades críticas (CVSS 9.2) en el **núcleo** del lenguaje: CVE-2026-109619 (use-after-free) y CVE-2026-109618 (corrupción de memoria por agotamiento). Ambas permiten ejecución remota de código **sin autenticación**.
>
> Lo relevante para su organización:
>
> - **El fallo está en PHP, no en su aplicación.** Su código puede ser correcto y el servidor seguir siendo explotable. La auditoría de código no cubre esto.
> - **Requisito por defecto.** `session.upload_progress.enabled=On` viene activo de fábrica. Solo hace falta un endpoint que acepte uploads.
> - **Impacto doble:** ejecución de comandos y lectura de memoria del proceso, lo que puede exponer datos de otros usuarios que compartan el worker (patrón Heartbleed).
> - **PHP 7.4 / 8.0 / 8.1 están fuera del ciclo regular.** PHP publicó backports mínimos de código fuente, pero sin releases periódicas: la actualización depende de su distro.
> - **Un WAF que mire el ritmo o el tamaño del body no lo frena.** La cadena es determinista; lo que sí la limita es el número de ficheros anidados.
>
> **Qué hacer:**
>
> 1. Inventariar la versión real de PHP en ejecución (no la del paquete).
> 2. Actualizar a 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 y reiniciar todos los workers.
> 3. Para 7.4 / 8.0 / 8.1: planificar migración o aplicar el backport de PHP.
> 4. Si no puede actualizar de inmediato: `session.upload_progress.enabled=0` (mitigación oficial de PHP, con una cobertura parcial) y `max_multipart_body_parts` / `max_file_uploads` acotados.
> 5. Revisar logs buscando `PHP_SESSION_UPLOAD_PROGRESS` en peticiones multipart y actividad anómala en `session.save_path`.
>
> **Propuesta Chain-Cortex:** auditoría de exposición PHP2Shell para su flota — inventario de versiones, verificación de exposición con test diferencial sobre servicios no-intrusivos, y validación de la remediación. El detector que usamos distingue vulnerable de parcheado sin necesidad de ejecutar exploits ni conocer offsets del binario.
>
> Detalle técnico completo, con laboratorio reproducible:
> https://github.com/santilpz28/php2shell-pub
>
> —
> *Chain-Cortex · Auditores de Smart Contracts y Arquitectos de Seguridad Web 2.5*

---

## Checklist de publicación

- [x] Repositorio público creado: `santilpz28/php2shell-pub`
- [x] Artículo completo en `BLOG.md` (secciones 1-11 + apéndices)
- [x] README como landing con estado, herramientas y remedios
- [x] `CITATION.cff` + bloque BibTeX
- [x] `NOTES-alloc-trace.md` con la bitácora de la instrumentación
- [x] Parches idempotentes (`patches/`) y target instrumentado (`Dockerfile.trace`)
- [x] Detector de exposición (`check_exposure.sh`, `behavioural_diff.py`)
- [ ] **Descripción del repo** (Settings → General) — texto arriba
- [ ] **Topics** (Settings → Topics) — lista arriba
- [ ] **Post de LinkedIn** publicado
- [ ] **Hilo de Twitter/X** publicado
- [ ] **Newsletter** enviada
- [ ] **Añadir el repo a `chainguard-pages` / CV** con enlace
- [ ] **Siguiente línea: escalar a RCE** (control del allocator sobre el slot del bin 6)

---

## Nota de precisión (importante para futuros posts)

Una versión anterior de este material afirmaba que **"PHP 7.4 es EOL sin parche,
vulnerable para siempre"**. **Es incorrecto** y se ha corregido en el README y
el BLOG el 27-oct-2026 a las 23:20: el proyecto PHP publicó backports mínimos
de código fuente para 7.4, 8.0 y 8.1 (verificado contra el advisory de
NCSC-NL y `GHSA-6wmf-4rv5-p3rp`). Lo que sí es cierto es que esas ramas no
reciben el ciclo regular de releases.

Antes de publicar cualquier afirmación sobre el estado de soporte de una
versión, verificarla contra la fuente primaria. En un artículo público, una
afirmación fuerte y errónea cuesta más credibilidad que la que aporta.
