# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 FSKY <development@fsky.io>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Example gibcert deploy hook for local Windows paths.
# Configure with:
#   $env:GIBCERT_DEPLOY_DIR = "C:\ProgramData\gibcert\tls\example.com"
# Optional:
#   $env:GIBCERT_DEPLOY_SERVICE = "nginx"

if ([string]::IsNullOrWhiteSpace($env:GIBCERT_DEPLOY_DIR)) {
    Write-Error "GIBCERT_DEPLOY_DIR is required"
    exit 2
}

$files = @(
    @(
        @{ Kind = "cert"; Path = $env:GIBCERT_CERT_PATH; Name = "cert.pem" },
        @{ Kind = "chain"; Path = $env:GIBCERT_CHAIN_PATH; Name = "chain.pem" },
        @{ Kind = "fullchain"; Path = $env:GIBCERT_FULLCHAIN_PATH; Name = "fullchain.pem" },
        @{ Kind = "key"; Path = $env:GIBCERT_KEY_PATH; Name = "privkey.pem" },
        @{ Kind = "cert-der"; Path = $env:GIBCERT_CERT_DER_PATH; Name = "cert.der" },
        @{ Kind = "key-der"; Path = $env:GIBCERT_KEY_DER_PATH; Name = "privkey.der" }
    ) | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.Path) -and (Test-Path -LiteralPath $_.Path -PathType Leaf)
    }
)

if ($files.Count -eq 0) {
    Write-Error "no gibcert deploy paths were set"
    exit 2
}

New-Item -ItemType Directory -Force -Path $env:GIBCERT_DEPLOY_DIR | Out-Null

foreach ($file in $files) {
    $target = Join-Path $env:GIBCERT_DEPLOY_DIR $file.Name
    $temp = Join-Path $env:GIBCERT_DEPLOY_DIR (".gibcert-{0}-{1}.tmp" -f $PID, $file.Name)
    Write-Host ("local-copy: copy {0} to {1}" -f $file.Kind, $target)
    Copy-Item -LiteralPath $file.Path -Destination $temp -Force
    Move-Item -LiteralPath $temp -Destination $target -Force
}

if (-not [string]::IsNullOrWhiteSpace($env:GIBCERT_DEPLOY_SERVICE)) {
    Write-Host ("local-copy: restart service {0}" -f $env:GIBCERT_DEPLOY_SERVICE)
    Restart-Service -Name $env:GIBCERT_DEPLOY_SERVICE -ErrorAction Stop
}
