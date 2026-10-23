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

{{/*
Database connection of the gateways: their own restricted role
(gateway.database.user), or the manager's account when it is empty.
*/}}
{{- define "openpicket.gatewayDBEnv" -}}
{{- $g := .Values.gateway.database -}}
{{- if $g.user -}}
- name: OPENPICKET_DATABASE_URL
  value: {{ printf "postgres://%s@%s:%s/%s?sslmode=%s&pool_max_conns=%d" $g.user (include "openpicket.dbHost" .) (include "openpicket.dbPort" .) .Values.database.openpicketDatabase (include "openpicket.dbSSLMode" .) (int .Values.database.maxConnections.gateway) | quote }}
- name: PGPASSWORD
  valueFrom:
    secretKeyRef:
      {{- include "openpicket.gatewayDBPasswordRef" . | nindent 6 }}
{{- else -}}
{{ include "openpicket.dbEnv" (list . .Values.database.maxConnections.gateway) }}
{{- end -}}
{{- end -}}

{{- define "openpicket.gatewayDBPasswordRef" -}}
name: {{ default (include "openpicket.secret" .) .Values.gateway.database.existingSecret }}
key: {{ ternary .Values.gateway.database.passwordKey "gateway-database-password" (not (empty .Values.gateway.database.existingSecret)) }}
{{- end -}}

{{/* Loki push (and the log explorer's reads). */}}
{{- define "openpicket.lokiEnv" -}}
- name: OPENPICKET_LOKI_URL
  value: {{ include "openpicket.lokiURL" . | quote }}
- name: OPENPICKET_LOKI_MAX_AGE
  value: {{ .Values.loki.maxAge | quote }}
{{- if not .Values.loki.builtin.enabled }}
- name: OPENPICKET_LOKI_TENANT
  value: {{ .Values.loki.external.tenant | quote }}
{{- with .Values.loki.external.queryURL }}
- name: OPENPICKET_LOKI_QUERY_URL
  value: {{ . | quote }}
{{- end }}
{{- if .Values.loki.external.username }}
- name: OPENPICKET_LOKI_USERNAME
  value: {{ .Values.loki.external.username | quote }}
- name: OPENPICKET_LOKI_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ default (include "openpicket.secret" .) .Values.loki.external.existingSecret }}
      key: {{ ternary .Values.loki.external.passwordKey "loki-password" (not (empty .Values.loki.external.existingSecret)) }}
{{- end }}
{{- end }}
{{- end -}}

{{/* CrowdSec log processors: records (8081) and content sync (8082). */}}
{{- define "openpicket.crowdsecSinkEnv" -}}
- name: OPENPICKET_CROWDSEC_DISCOVERY_HOST
  value: {{ include "openpicket.fullname" . }}-crowdsec-agents
- name: OPENPICKET_CROWDSEC_DISCOVERY_PORT
  value: "8081"
- name: OPENPICKET_CROWDSEC_AUTH_HEADER
  value: X-OpenPicket-Token
- name: OPENPICKET_CROWDSEC_AUTH_VALUE
  valueFrom:
    secretKeyRef:
      name: {{ include "openpicket.secret" . }}
      key: acquis-token
{{- end -}}

{{/* OpenSearch: the record sink (gateway) and the alert index (manager). */}}
{{- define "openpicket.opensearchEnv" -}}
{{- if .Values.opensearch.enabled }}
- name: OPENPICKET_OPENSEARCH_URL
  value: {{ required "opensearch.url is required" .Values.opensearch.url | quote }}
- name: OPENPICKET_OPENSEARCH_RETENTION
  value: {{ .Values.opensearch.retention | quote }}
- name: OPENPICKET_OPENSEARCH_REPLICAS
  value: {{ .Values.opensearch.replicas | quote }}
- name: OPENPICKET_OPENSEARCH_INSECURE_SKIP_VERIFY
  value: {{ .Values.opensearch.insecureSkipVerify | quote }}
{{- if .Values.opensearch.username }}
- name: OPENPICKET_OPENSEARCH_USERNAME
  value: {{ .Values.opensearch.username | quote }}
- name: OPENPICKET_OPENSEARCH_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ default (include "openpicket.secret" .) .Values.opensearch.existingSecret }}
      key: {{ ternary .Values.opensearch.passwordKey "opensearch-password" (not (empty .Values.opensearch.existingSecret)) }}
{{- end }}
{{- if .Values.opensearch.caSecret }}
- name: OPENPICKET_OPENSEARCH_CA_FILE
  value: /secrets/opensearch-ca/ca.crt
{{- end }}
{{- end }}
{{- end -}}

{{/* The key secret the UI/API keys derive from (every role). */}}
{{- define "openpicket.keySecretEnv" -}}
- name: OPENPICKET_KEY_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "openpicket.secret" . }}
      key: key-secret
{{- end -}}
