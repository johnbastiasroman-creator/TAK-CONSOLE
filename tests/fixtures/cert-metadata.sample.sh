# Muestra sintética con las mismas variables que cert-metadata.sh de TAK Server
COUNTRY=US
STATE=${STATE}
CITY=${CITY}
ORGANIZATION=${ORGANIZATION:-TAK}
ORGANIZATIONAL_UNIT=${ORGANIZATIONAL_UNIT}

CAPASS=${CAPASS:-atakatak}
PASS=${PASS:-$CAPASS}

DIR=files
