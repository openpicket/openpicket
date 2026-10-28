{{/* Names */}}
{{- define "collector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 50 | trimSuffix "-" -}}
{{- else if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "collector.selector" -}}
app.kubernetes.io/name: openpicket-agent-k8s-collector
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "collector.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/part-of: openpicket
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{ include "collector.selector" . }}
{{- end -}}

{{- define "collector.image" -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.registry -}}{{- $repo = printf "%s/%s" (trimSuffix "/" .Values.image.registry) $repo -}}{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "collector.serviceAccount" -}}
{{- if .Values.serviceAccount.create -}}{{ default (include "collector.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ default "default" .Values.serviceAccount.name }}{{- end -}}
{{- end -}}

{{/* The node key's secret and key. */}}
{{- define "collector.keySecret" -}}
{{- default (printf "%s-key" (include "collector.fullname" .)) .Values.key.existingSecret -}}
{{- end -}}
{{- define "collector.keyKey" -}}
{{- if .Values.key.existingSecret -}}{{ .Values.key.secretKey }}{{- else -}}agent_ed25519{{- end -}}
{{- end -}}

{{/* Namespaces the collector reads: the targets' and rbac.extraNamespaces. */}}
{{- define "collector.namespaces" -}}
{{- $ns := list -}}
{{- range .Values.targets -}}{{- $ns = append $ns .namespace -}}{{- end -}}
{{- range .Values.rbac.extraNamespaces -}}{{- $ns = append $ns . -}}{{- end -}}
{{- $ns | uniq | sortAlpha | toJson -}}
{{- end -}}

{{- define "collector.configDir" -}}/etc/openpicket-agent-k8s-collector{{- end -}}
{{- define "collector.stateDir" -}}/var/lib/openpicket-agent-k8s-collector{{- end -}}

{{/* The configuration file. */}}
{{- define "collector.config" -}}
{{- $op := dict "url" (required "openpicket.url is required" .Values.openpicket.url) "host_key" (required "openpicket.hostKey is required (Nodes > Connection info)" .Values.openpicket.hostKey) -}}
{{- with .Values.openpicket.headers }}{{ $_ := set $op "headers" . }}{{ end -}}
{{- if .Values.openpicket.caCert }}{{ $_ := set $op "ca_file" (printf "%s/ca.crt" (include "collector.configDir" .)) }}{{ end -}}
{{- if .Values.openpicket.tlsInsecureSkipVerify }}{{ $_ := set $op "tls_insecure_skip_verify" true }}{{ end -}}
{{- with .Values.openpicket.inflightMaxBytes }}{{ $_ := set $op "inflight_max_bytes" . }}{{ end -}}
{{- $cfg := dict "node_id" (required "nodeId is required" .Values.nodeId) "key_file" (printf "%s/key/agent_ed25519" (include "collector.configDir" .)) "log_level" .Values.logLevel "scan_interval" .Values.scanInterval "openpicket" $op -}}
{{- if .Values.state.enabled }}{{ $_ := set $cfg "state_file" (printf "%s/positions.json" (include "collector.stateDir" .)) }}{{ end -}}
{{- if not .Values.targets }}{{ fail "targets: at least one target is required" }}{{ end -}}
{{- $_ := set $cfg "targets" .Values.targets -}}
{{- toYaml $cfg -}}
{{- end -}}
