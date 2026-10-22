{{/*
Database connection of the manager and suricontroller (pgx reads PGPASSWORD),
with the pool size of one pod: include "openpicket.dbEnv" (list . 6)
*/}}
{{- define "openpicket.dbEnv" -}}
{{- $root := index . 0 -}}
- name: OPENPICKET_DATABASE_URL
  value: {{ printf "%s&pool_max_conns=%d" (include "openpicket.databaseURL" $root) (int (index . 1)) | quote }}
- name: PGPASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "openpicket.dbPasswordSecret" $root }}
      key: {{ include "openpicket.dbPasswordKey" $root }}
{{- end -}}

{{- define "openpicket.hostKeySecret" -}}
{{- default (include "openpicket.secret" .) .Values.manager.existingHostKeySecret -}}
{{- end -}}
