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

# Example gibcert deploy hook for rclone destinations.
# Configure with:
#   $env:GIBCERT_RCLONE_DESTS = "remote1:/path remote2:/path"
# Optional:
#   $env:GIBCERT_RCLONE = "C:\path\to\rclone.exe"

$rclone = if ([string]::IsNullOrWhiteSpace($env:GIBCERT_RCLONE)) { "rclone" } else { $env:GIBCERT_RCLONE }

if ([string]::IsNullOrWhiteSpace($env:GIBCERT_RCLONE_DESTS)) {
    Write-Error "GIBCERT_RCLONE_DESTS is required"
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

$destinations = $env:GIBCERT_RCLONE_DESTS -split '\s+' | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
}

foreach ($dest in $destinations) {
    $dest = $dest.TrimEnd("/")
    foreach ($file in $files) {
        $certName = if ($env:GIBCERT_CERT) { $env:GIBCERT_CERT } else { "cert" }
        $temp = "{0}/.gibcert-{1}-{2}-{3}" -f $dest, $certName, $PID, $file.Name
        $final = "{0}/{1}" -f $dest, $file.Name
        Write-Host ("rclone: copy {0} to {1}" -f $file.Kind, $final)
        & $rclone copyto $file.Path $temp
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $rclone moveto $temp $final
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}
