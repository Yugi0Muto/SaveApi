#!/usr/bin/env bash
# lib/indexer_expose.sh — rendre l'indexer joignable sur l'IP du serveur (Grafana sur une autre machine),
# APRÈS une installation tout-en-un officielle (qui le limite à 127.0.0.1).
#
# Pourquoi ainsi : la procédure officielle « en plusieurs commandes » (config.yml, --start-cluster,
# --wazuh-server…) échoue de façon intermittente (« The Wazuh API user wazuh does not exist », puis
# annulation complète). L'installation tout-en-un est la plus éprouvée ; on l'ouvre ensuite proprement :
#   1. nouveau certificat de l'indexer : MÊME clé, MÊME sujet (donc même identité de nœud pour le module
#      de sécurité), signé par la MÊME autorité (root-ca de l'installation), avec l'IP du serveur ajoutée
#      aux adresses (SAN) — 127.0.0.1 reste valable pour le manager, Filebeat et le dashboard ;
#   2. écoute sur 127.0.0.1 ET sur l'IP (network.host) ;
#   3. redémarrage, puis test HTTPS sur l'IP avec vérification du certificat.
# En cas d'échec : certificat et configuration d'origine restaurés, indexer redémarré.

# reissue_indexer_cert CERT KEY CA_PEM CA_KEY IP SORTIE : réémet CERT avec IP ajoutée (fonction pure, testable)
reissue_indexer_cert() {
  local cert="$1" key="$2" ca="$3" cakey="$4" ip="$5" out="$6" w sans
  w="$(mktemp -d)"
  sans="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr ',' '\n' \
          | sed -E 's/^[[:space:]]+//; s/^IP Address:/IP:/' | grep -E '^(IP|DNS):' || true)"
  grep -qx "IP:$ip" <<< "$sans" || sans="$(printf '%s\nIP:%s' "$sans" "$ip" | sed '/^$/d')"
  grep -qx "IP:127.0.0.1" <<< "$sans" || sans="$(printf '%s\nIP:127.0.0.1' "$sans")"
  cat > "$w/ext.cnf" <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = $(paste -sd, <<< "$sans")
EOF
  openssl x509 -x509toreq -in "$cert" -signkey "$key" -out "$w/req.csr" 2>"$w/err" \
    && openssl x509 -req -in "$w/req.csr" -CA "$ca" -CAkey "$cakey" -CAserial "$w/ca.srl" -CAcreateserial \
         -days 3650 -sha256 -extfile "$w/ext.cnf" -extensions v3_req -out "$out" 2>>"$w/err" \
    && openssl verify -CAfile "$ca" "$out" >/dev/null 2>>"$w/err" \
    || { cat "$w/err" >&2; rm -rf "$w"; return 1; }
  rm -rf "$w"
}

# expose_indexer IP : applique la procédure sur le serveur (nécessite common.sh et l'archive de l'installation)
expose_indexer() {
  local ip="$1" certs=/etc/wazuh-indexer/certs yml=/etc/wazuh-indexer/opensearch.yml tarf w bak code
  tarf="$SECRETS_DIR/wazuh-install-files.tar"
  [[ -f "$tarf" ]] || die "Archive $tarf absente : impossible de signer un certificat avec l'autorité de l'installation."
  explain <<TXT
Ouverture de l'indexer sur ${ip} (pour un Grafana installé sur une autre machine) :
  1. certificat de l'indexer réémis avec l'adresse ${ip} (même clé, même identité, même autorité) ;
  2. écoute sur 127.0.0.1 et sur ${ip} ;
  3. test HTTPS sur ${ip}:9200 avec vérification du certificat.
Le port 9200 ne doit être autorisé, sur le pare-feu de l'entreprise, QUE pour la machine Grafana.
En cas d'échec, tout est remis dans l'état d'origine.
TXT
  w="$(mktemp -d)"; chmod 700 "$w"
  bak="$certs/avant-ouverture-$(date +%Y%m%d-%H%M%S)"
  run "Extraction de l'autorité de certification de l'installation (dossier temporaire root)" \
    tar -xf "$tarf" -C "$w" wazuh-install-files/root-ca.pem wazuh-install-files/root-ca.key
  run "Sauvegarde du certificat et de la configuration de l'indexer" \
    bash -c "mkdir -p '$bak' && cp -p '$certs/indexer.pem' '$bak/' && cp -p '$yml' '$bak/'"
  if ! run --allow-fail "Réémission du certificat de l'indexer avec l'adresse $ip" \
       reissue_indexer_cert "$certs/indexer.pem" "$certs/indexer-key.pem" "$w/wazuh-install-files/root-ca.pem" \
       "$w/wazuh-install-files/root-ca.key" "$ip" "$w/indexer.pem"; then
    rm -rf "$w"; die "Réémission du certificat impossible (message ci-dessus) : rien n'a été modifié."
  fi
  run "Adresses contenues dans le nouveau certificat" openssl x509 -in "$w/indexer.pem" -noout -ext subjectAltName
  run "Installation du nouveau certificat" install -o wazuh-indexer -g wazuh-indexer -m 400 "$w/indexer.pem" "$certs/indexer.pem"
  rm -rf "$w"   # la clé de l'autorité ne reste pas sur le disque en clair hors de l'archive
  run "Écoute sur 127.0.0.1 et $ip (network.host)" \
    sed -i -E "s|^[#[:space:]]*network\.host:.*|network.host: [\"127.0.0.1\", \"$ip\"]|" "$yml"
  run "Vérification de la configuration" grep -E '^network\.host:' "$yml"
  if (( $(sysctl -n vm.max_map_count 2>/dev/null || echo 0) < 262144 )); then
    run "Paramètre noyau requis par l'indexer (vm.max_map_count)" sysctl -w vm.max_map_count=262144
    printf 'vm.max_map_count=262144\n' > /etc/sysctl.d/99-wazuh-bundle.conf
  fi
  run "Redémarrage de l'indexer" systemctl restart wazuh-indexer
  log_info "Attente de l'indexer sur https://$ip:9200 (2 min max)…"
  code=000
  for _ in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$certs/root-ca.pem" "https://$ip:9200/" || true)"
    [[ "$code" == 401 || "$code" == 200 ]] && break
    sleep 3
  done
  if [[ "$code" == 401 || "$code" == 200 ]]; then
    log_ok "Indexer joignable sur https://$ip:9200, certificat vérifié (HTTP $code sans identifiant : attendu)."
    return 0
  fi
  log_err "L'indexer ne répond pas correctement sur https://$ip:9200 (HTTP ${code}) : retour à l'état d'origine."
  run --allow-fail "Journal de l'indexer" journalctl -u wazuh-indexer -n 30 --no-pager || true
  cp -p "$bak/indexer.pem" "$certs/indexer.pem"; cp -p "$bak/opensearch.yml" "$yml"
  run --allow-fail "Redémarrage de l'indexer (configuration d'origine)" systemctl restart wazuh-indexer || true
  die "Ouverture de l'indexer impossible : configuration d'origine restaurée (indexer sur 127.0.0.1)."
}
