{{- define "ales.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ales.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ales.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ales.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ales.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ales.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "ales.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ales.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "ales.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "ales.secretName" -}}
{{- required "secrets.existingSecret is required (no inline secrets are supported)" .Values.secrets.existingSecret -}}
{{- end -}}

{{/* Env shared by the app container and the migration job's DB access. */}}
{{- define "ales.databaseEnv" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "ales.secretName" . }}
      key: {{ .Values.secrets.keys.databaseUrl }}
{{- end -}}
