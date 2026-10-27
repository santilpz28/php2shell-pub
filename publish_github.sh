#!/bin/bash
# Publica el laboratorio PHP2Shell en github.com/santilpz28/php2shell-lab
#
# Prerequisito: el repo DEBE existir (vacio) en GitHub. GitHub no permite
# crear repos mediante push por SSH, y esta maquina no tiene ningun PAT
# con permisos de API guardado.
#
#   https://github.com/new?name=php2shell-lab
#
# Uso:  bash publish_github.sh
set -euo pipefail

REPO="git@github.com:santilpz28/php2shell-lab.git"
STAGE="/tmp/php2shell-pub"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Publicando PHP2Shell → $REPO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -d "$STAGE/.git" ]; then
    echo "❌ No existe el staging en $STAGE"
    exit 1
fi

cd "$STAGE"

echo "→ Verificando que el repo remoto existe..."
if ! git ls-remote "$REPO" >/dev/null 2>&1; then
    echo "❌ El repo remoto no existe o no es accesible."
    echo "   Crealo aqui: https://github.com/new?name=php2shell-lab"
    echo "   (sin inicializar README, .gitignore ni licencia)"
    exit 1
fi

echo "→ Push..."
git push -u origin main --force

echo "→ Verificando por API pública..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "https://api.github.com/repos/santilpz28/php2shell-lab")
echo "  https://github.com/santilpz28/php2shell-lab → HTTP $HTTP"
echo
echo "✅ Publicado. No olvides setear la descripcion y los topics en GitHub:"
echo "   topics: php, security, cve, rce, use-after-free, vulnerability-research"
