{{/* Database connection of the manager and suricontroller (pgx reads PGPASSWORD). */}}
{{- define "openpicket.dbEnv" -}}
- name: OPENPICKET_DATABASE_URL
  value: {{ include "openpicket.databaseURL" . | quote }}
- name: PGPASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "openpicket.dbPasswordSecret" . }}
      key: {{ include "openpicket.dbPasswordKey" . }}
{{- end -}}

{{- define "openpicket.hostKeySecret" -}}
{{- default (include "openpicket.secret" .) .Values.manager.existingHostKeySecret -}}
{{- end -}}
