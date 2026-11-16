#!/usr/bin/env bash
# install_yara.sh — installe YARA (manager ET agents Linux), version épinglée et vérifiée.
#
#   bash tools/install_yara.sh [--method source|package]
#
#   source  (recommandé) : YARA 4.5.8, dernière version stable de la branche 4.x (VirusTotal), compilée
#                          depuis le dépôt officiel. L'identité du code est vérifiée : le tag v4.5.8 doit
#                          pointer EXACTEMENT sur le commit ci-dessous, sinon l'installation s'arrête.
#                          Installé dans /usr/local/bin/yara.
#   package              : paquet de la distribution (plus simple, mais version plus ancienne :
#                          Debian 12 = 4.2.x, Ubuntu 24.04 = 4.5.0). Installé dans /usr/bin/yara.
# Idempotent : ne recompile pas si la bonne version est déjà présente.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root

YARA_VERSION="4.5.8"
YARA_TAG="v${YARA_VERSION}"
YARA_COMMIT="84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8"
YARA_REPO="https://github.com/VirusTotal/yara.git"

METHOD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --method) METHOD="$2"; shift 2;;
    *) die "Argument inconnu : $1";;
  esac
done
if [[ -z "$METHOD" ]]; then
  ask_choice YARA_INSTALL_METHOD "Méthode d'installation de YARA" source \
    "source|Compiler YARA ${YARA_VERSION} (dernière version stable, recommandé ; ~3 min)" \
    "package|Paquet de la distribution (plus ancien, aucune compilation)"
  METHOD="$YARA_INSTALL_METHOD"
fi

if [[ "$METHOD" == package ]]; then
  pkg_install yara
  run "Version de YARA installée" yara --version
  exit 0
fi
[[ "$METHOD" == source ]] || die "Méthode inconnue : $METHOD (source ou package)"

if [[ -x /usr/local/bin/yara ]] && [[ "$(/usr/local/bin/yara --version 2>/dev/null)" == "$YARA_VERSION" ]]; then
  log_ok "YARA $YARA_VERSION déjà installé (/usr/local/bin/yara) : rien à faire."; exit 0
fi

explain <<TXT
Compilation de YARA ${YARA_VERSION} :
  1. installation des outils de compilation et des bibliothèques (OpenSSL pour les modules hash/pe,
     libmagic pour le module magic, jansson pour les modules cuckoo/dotnet) ;
  2. téléchargement du code source officiel (${YARA_REPO}, tag ${YARA_TAG}) ;
  3. vérification que le tag correspond au commit attendu ${YARA_COMMIT:0:12}… ;
  4. compilation, installation dans /usr/local, test sur le fichier EICAR.
TXT
pkg_install git automake libtool make gcc pkg-config flex bison libssl-dev libjansson-dev libmagic-dev
BUILD="$(mktemp -d /usr/local/src/yara-build-XXXXXX)"
trap 'rm -rf "$BUILD"' EXIT
run --hint "Accès HTTPS à github.com requis (proxy ? pare-feu sortant ?)" \
  "Téléchargement du code source YARA $YARA_TAG" git -c advice.detachedHead=false clone --depth 1 --branch "$YARA_TAG" "$YARA_REPO" "$BUILD/yara"
got="$(git -C "$BUILD/yara" rev-parse HEAD)"
echo "  commit obtenu : $got"; echo "  commit attendu: $YARA_COMMIT"
[[ "$got" == "$YARA_COMMIT" ]] || die "Le code téléchargé ne correspond PAS au commit attendu : installation refusée (dépôt modifié ou intercepté)."
log_ok "Identité du code source vérifiée."
cd "$BUILD/yara"
run --quiet "Préparation (bootstrap.sh)" ./bootstrap.sh
run --quiet --hint "Une bibliothèque de développement manque : relire la fin de la sortie (« checking for … no »)." \
  "Configuration de la compilation" ./configure --prefix=/usr/local --enable-magic --enable-dotnet --with-crypto
run --quiet "Compilation ($(nproc) cœurs)" make -j"$(nproc)"
run --quiet "Installation dans /usr/local" make install
run "Mise à jour du cache des bibliothèques" ldconfig
v="$(/usr/local/bin/yara --version)"
[[ "$v" == "$YARA_VERSION" ]] || die "Version installée inattendue : $v"
log_ok "YARA $v installé : /usr/local/bin/yara"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$BUILD/eicar.txt"
printf 'rule EICAR_Test { strings: $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $e }\n' > "$BUILD/t.yar"
run "Test fonctionnel : YARA doit reconnaître le fichier de test EICAR" /usr/local/bin/yara "$BUILD/t.yar" "$BUILD/eicar.txt"
grep -q EICAR_Test <<< "$RUN_OUTPUT" || die "YARA n'a pas détecté le fichier EICAR : installation défectueuse."
