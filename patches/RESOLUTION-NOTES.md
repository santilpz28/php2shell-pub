# Notas de resolución del backport — PHP2Shell sobre PHP 8.2.34

Documento de referencia del proceso de backport del parche oficial
"Avoid state corruption via bailout" sobre **PHP 8.2.34**, sin cambiar de
versión. Todo lo que sigue está verificado empíricamente (ver
"Reproducción" al final).

---

## 1. Qué commits existen

| Commit | Rama | Ficheros | Qué es |
|---|---|---|---|
| `31c0ea7d7ff1d1fccb6492e52dab544011628065` | `PHP-8.2` (upstream) | **423** | Fix completo. Reescribe el allocator de Zend MM. Etiquetado `php-8.2.35`. |
| `01a40e89fb…` | `PHP-8.2.35` | — | Cherry-pick del anterior sobre la tag de release. |
| `3c832b523e…` | `PHP-8.3.36` | — |ídem para 8.3. |
| `506e87fa7d…` | `PHP-8.4.27` | — | Ídem para 8.4. |
| `3584a98bda…` | `PHP-8.3`/`8.4`/`8.5` | — | Backport del fix completo a las ramas de desarrollo. |
| `1d7dec178a094e6e75b229ce22754045f8c6070a` | `PHP-8.1-CVE-2026-109618-109619` | **23** | **Minimal mitigation for EOL version.** |
| `82f8f31b16a035c1b67cc253e79f7cc288f4cc20` | `PHP-8.0-CVE-2026-109618-109619` | 23 | Ídem. |
| `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2` | `PHP-7.4-CVE-2026-109618-109619` | 23 | Ídem. |

Todos los commits llevan el mismo mensaje y las mismas referencias:

```
Avoid state corruption via bailout

Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
```

**Cuidado con un falso positivo fácil:** el commit `ed70b1ea`
("Fix GHSA-www2-q4fc-65wf") y el `8b801151` ("Fix GHSA-h96m-rvf9-jgm2")
también aparecen en esas ramas, pero **no** son los CVEs de PHP2Shell
(son DNS rebinding y un null-deref de array). El que nos interesa es
`1d7dec17`.

## 2. Por qué NO se usa el commit upstream de 8.2

El commit `31c0ea7d7ff` reescribe el allocator de Zend MM: `Zend/zend_alloc.c`
sufre 651 líneas de cambios, y toca `zend_hash.c`, `zend_string.c`,
`zend_operators.c`, el VM, OPcache, y una docena de extensiones.

Probado con `git cherry-pick --no-commit 31c0ea7d7ff` sobre el tag
`php-8.2.34`: **conflictos de contenido en el núcleo del motor**, entre otros:

```
CONFLICT (content): Merge conflict in Zend/zend.c
CONFLICT (content): Merge conflict in Zend/zend_alloc.c
CONFLICT (content): Merge conflict in Zend/zend_alloc.h
CONFLICT (content): Merge conflict in Zend/zend_attributes.c
CONFLICT (content): Merge conflict in Zend/zend_builtin_functions.c
CONFLICT (content): Merge conflict in Zend/zend_execute.c
CONFLICT (content): Merge conflict in Zend/zend_hash.c
...
```

No es un parche "drop-in". Resolverlo a mano sobre un build de producción
es exactamente el tipo de operación que no quieres hacer un viernes.

## 3. Por qué SÍ se usa el commit de la rama EOL

El commit `1d7dec17` de la rama 8.1 es **el mismo fix reducido a su forma
mínima**, escrito explícitamente para las ramas sin soporte. Toca 23
ficheros, de los cuales **5 son de código** y 18 son tests `.phpt`.

Aplicado sobre `php-8.2.34` con `git cherry-pick --no-commit`:

```
CONFLICT: Zend/zend_alloc.c
CONFLICT: ext/opcache/zend_file_cache.c
CONFLICT: ext/zend_test/tests/observer_bug81430_2.phpt   <- solo test
CONFLICT: ext/zend_test/tests/observer_error_01.phpt      <- solo test
CONFLICT: main/rfc1867.c
```

**3 conflictos en código real**, ninguno trivial-sin-pensar, ninguno en el
allocator de forma irreversible.

## 4. Resolución de cada conflicto

### 4.1 `Zend/zend_alloc.c` — `abort()` vs `_exit(1)`

El fichero tiene **dos** OCC (occurrence conflicts) en este punto.

**(a) El include.** HEAD (8.2.34) tiene `#include "zend_mmap.h"`; el parche
añade `#include "zend_execute.h"`. Se conservan **ambos**: no son
excluyentes.

```c
 #include "zend_bitset.h"
+#include "zend_mmap.h"     <- de HEAD
+#include "zend_execute.h"  <- del parche
 #include <signal.h>
```

**(b) La salida por OOM.** Aquí está el fondo del asunto:

| | 8.2.34 (HEAD) | parche (rama EOL) |
|---|---|---|
| `zend_out_of_memory()` | `exit(1)` | `_exit(1)` |

`exit(1)` ejecuta los handlers `atexit` → flush de buffers → **unwinding a
través de la VM**. Ese unwinding es precisamente lo que corrompe el estado
del allocator: deja punteros colgando en globals que sobreviven al worker.
`_exit(1)` no ejecuta nada de eso: mata el proceso de golpe.

**Gana el parche.** Pero aquí aparece un detalle que no sale del `cherry-pick`:

> 8.2.34 **ya define** `zend_out_of_memory()` (línea 2792, con `exit(1)`).
> El commit de la rama 8.1 la define en la línea 3112 (con `_exit(1)`).
> En la rama 8.1 no había definición previa, por eso el parche no genera
> conflicto — **pero al aplicarlo sobre 8.2.34 se produce una
> redefinición**, y el compilador falla con:
>
> ```
> /…/Zend/zend_alloc.c:2820:37: error: redefinition of 'zend_out_of_memory'
> ```
>
> Este **no es un conflicto textual**: `git apply` lo acepta sin quejarse y
> el fallo solo aparece al compilar. Es el tipo de conflicto semántico que
> sólo aparece al enlazar.

**Resolución:** eliminar la definición de HEAD (la que usa `exit(1)`) y
conservar la del parche (la que usa `_exit(1)`). El efecto neto es el que
busca el parche: el OOM ya no hace unwinding.

```c
-static ZEND_COLD ZEND_NORETURN void zend_out_of_memory(void)
-{
-	fprintf(stderr, "Out of memory\n");
-	exit(1);
-}
-
```

### 4.2 `main/rfc1867.c` — cast de `isspace()`

8.2.34 ya tenía aplicado el fix de seguridad de `isspace()` (cast a
`unsigned char`). El parche de la rama EOL mueve ese `do { value++; } while
(isspace(...))` dentro de un bloque nuevo (el filtrado de cabeceras
multipart).

Conflicto puramente cosmético: se conserva el cast de HEAD.

```c
-			do { value++; } while (isspace(*value));
+			do { value++; } while (isspace((unsigned char)*value));
```

### 4.3 `ext/opcache/zend_file_cache.c` — `bool` vs `int`

HEAD (8.2.34) usa `bool ok` (C99); el parche de 8.1 usa `int ok`. No es
incompatible: `bool` es un `int` con restriction de rango. Se conserva
`bool` de HEAD y se añade la variable nueva que el parche necesita.

```c
-	bool ok;
+	bool ok;                      <- de HEAD
+	size_t orig_map_ptr_last = 0; <- del parche
```

`orig_map_ptr_last` es imprescindible: el parche guarda el valor original de
`CG(map_ptr_last)` para poder **restaurarlo** si la deserialización falla
(`zend_accel_pending_ce_cache_discard(); CG(map_ptr_last) = orig_map_ptr_last;`).
Es el mecanismo que evita que un fallo a mitad de carga del script deje el
estado del allocator de OPcache a medias.

### 4.4 Los tests `.phpt`

Los dos conflictos están en `ext/zend_test/tests/`. Son tests de observador
que no existen en la misma forma en 8.2.34. Se resuelven quedándose con la
versión de HEAD: no afectan al binario.

## 5. Ficheros de código afectados por el backport

```
Zend/zend_API.h
Zend/zend_alloc.c          <- exit(1) -> _exit(1)
Zend/zend_alloc.h
Zend/zend_execute_API.c
Zend/zend_hash.c
Zend/zend_hash.h
Zend/zend_multiply.h       <- zend_error_noreturn -> zend_mm_safe_error_ex
Zend/zend_strtod.c
Zend/zend_types.h
Zend/zend_vm_def.h
Zend/zend_vm_execute.h
ext/opcache/ZendAccelerator.c
ext/opcache/ZendAccelerator.h
ext/opcache/zend_file_cache.c
ext/opcache/zend_persist.c
ext/session/session.c       <- el hunk que desactiva el callback
main/SAPI.c
main/main.c
main/php_variables.c
main/rfc1867.c
```

20 ficheros de código. El hunk de `ext/session/session.c` es el que corta la
cadena de ataque:

```c
-	if (!PS(rfc1867_enabled)) {
+	if (!PS(rfc1867_enabled) || true) {
 		return retval;
 	}
```

Es una mitigación **todo o nada**: con el parche aplicado, el callback de
upload_progress queda permanentemente desactivado, y la rama CVE-2026-109619
—que necesita ese callback para consumir el estado de sesión colgante— nunca
llega a ejecutarse.

## 6. Reproducción

```bash
# Construir la imagen parcheada (misma versión, código corregido)
docker build -f Dockerfile.backport -t php2shell-backport:8.2.34 .

# Comprobar la huella del parche en el código
python3 verify_backport.py --source <árbol de fuentes>

# Comportamiento diferencial contra los tres targets
python3 behavioural_diff.py 127.0.0.1 8080 "8.2.34 SIN parche"
python3 behavioural_diff.py 127.0.0.1 8081 "8.2.35 oficial"
python3 behavioural_diff.py 127.0.0.1 8082 "8.2.34 + backport"
```

## 7. Limitación honesta de esta variante

El backport de la rama EOL es una **mitigación mínima**, no el fix completo
de upstream. En concreto:

- Desactiva el callback de `upload_progress` de forma permanente. Esto corta
  la cadena de ataque, pero también **desactiva una funcionalidad legítima**
  de PHP (el tracking de progreso de uploads). Para un sitio que use
  `session.upload_progress` para barra de progreso, es un cambio de
  comportamiento observable.
- No incluye el trabajo de `UnwindExit` ni el saneamiento completo del
  allocator que hace el commit upstream de 423 ficheros.

**Cuándo usar cada vía:**

| Situación | Vía recomendada |
|---|---|
| PHP 8.2+ con capacidad de actualizar | **Actualizar a 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.** Es lo correcto. |
| PHP 8.2+ que no puede cambiar de versión (deps, extensiones PECL, ABI) | **Backport del commit** (este documento). |
| PHP 7.4 / 8.0 / 8.1 | **Paquete parcheado de la distro** (Sury, Remi, AlmaLinux…) o backport equivalente. |
| No se puede tocar PHP ahora | Mitigaciones: `session.upload_progress.enabled=0`, `max_multipart_body_parts`, `max_file_uploads`, bloqueo de `multipart/form-data` en el servidor web. |

La regla de oro sigue siendo: **parchear, no reescribir**. Un parche conserva
el número de versión, las extensiones y el ABI. Una actualización cambia las
tres cosas.
