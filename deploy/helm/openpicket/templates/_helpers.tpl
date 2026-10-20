{{/* Names */}}
{{- define "openpicket.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "openpicket.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/part-of: openpicket
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/* Selector labels of a component: include "openpicket.selector" (list . "manager") */}}
{{- define "openpicket.selector" -}}
app.kubernetes.io/name: openpicket
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "openpicket.componentLabels" -}}
{{ include "openpicket.labels" (index . 0) }}
{{ include "openpicket.selector" . }}
{{- end -}}

{{/* image: include "openpicket.image" (list . .Values.manager.image) */}}
{{- define "openpicket.image" -}}
{{- $root := index . 0 -}}
{{- $img := index . 1 -}}
{{- $registry := $root.Values.global.imageRegistry -}}
{{- $repo := $img.repository -}}
{{- if $registry -}}{{- $repo = printf "%s/%s" (trimSuffix "/" $registry) $repo -}}{{- end -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $repo $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default $root.Chart.AppVersion $img.tag) -}}
{{- end -}}
{{- end -}}

{{- define "openpicket.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Name of the generated secret. */}}
{{- define "openpicket.secret" -}}{{ include "openpicket.fullname" . }}-secrets{{- end -}}

{{/*
A generated secret value that survives upgrades: the value from values,
else the one already in the cluster, else a new random one.
include "openpicket.secretValue" (list . "key" .Values.some.value 32)
*/}}
{{- define "openpicket.secretValue" -}}
{{- $root := index . 0 -}}
{{- $key := index . 1 -}}
{{- $given := index . 2 -}}
{{- $len := index . 3 -}}
{{- if $given -}}
{{- $given -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" $root.Release.Namespace (include "openpicket.secret" $root) -}}
{{- if and $existing (index $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- randAlphaNum $len -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Database */}}
{{- define "openpicket.dbHost" -}}
{{- if .Values.database.builtin.enabled -}}{{ include "openpicket.fullname" . }}-postgres{{- else -}}{{ required "database.external.host is required" .Values.database.external.host }}{{- end -}}
{{- end -}}
{{- define "openpicket.dbPort" -}}
{{- if .Values.database.builtin.enabled -}}5432{{- else -}}{{ .Values.database.external.port }}{{- end -}}
{{- end -}}
{{- define "openpicket.dbUser" -}}
{{- if .Values.database.builtin.enabled -}}openpicket{{- else -}}{{ required "database.external.user is required" .Values.database.external.user }}{{- end -}}
{{- end -}}
{{- define "openpicket.dbSSLMode" -}}
{{- if .Values.database.builtin.enabled -}}disable{{- else -}}{{ .Values.database.external.sslmode }}{{- end -}}
{{- end -}}
{{/* Secret and key holding the database password. */}}
{{- define "openpicket.dbPasswordSecret" -}}
{{- if and (not .Values.database.builtin.enabled) .Values.database.external.existingSecret -}}{{ .Values.database.external.existingSecret }}{{- else -}}{{ include "openpicket.secret" . }}{{- end -}}
{{- end -}}
{{- define "openpicket.dbPasswordKey" -}}
{{- if and (not .Values.database.builtin.enabled) .Values.database.external.existingSecret -}}{{ .Values.database.external.passwordKey }}{{- else -}}database-password{{- end -}}
{{- end -}}
{{- define "openpicket.databaseURL" -}}
postgres://{{ include "openpicket.dbUser" . }}@{{ include "openpicket.dbHost" . }}:{{ include "openpicket.dbPort" . }}/{{ .Values.database.openpicketDatabase }}?sslmode={{ include "openpicket.dbSSLMode" . }}
{{- end -}}

{{/* Loki */}}
{{- define "openpicket.lokiURL" -}}
{{- if .Values.loki.builtin.enabled -}}http://{{ include "openpicket.fullname" . }}-loki:3100{{- else -}}{{ required "loki.external.url is required" .Values.loki.external.url }}{{- end -}}
{{- end -}}

{{- define "openpicket.lapiURL" -}}http://{{ include "openpicket.fullname" . }}-crowdsec-lapi:8080{{- end -}}
