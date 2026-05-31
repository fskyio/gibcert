// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 FSKY <development@fsky.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"sort"

	"foundry.fsky.io/fsky/gibcert/internal/config"
	"foundry.fsky.io/fsky/gibcert/internal/paths"
	"foundry.fsky.io/fsky/gibcert/internal/storage"
)

const completionUsage = `usage: gibcert completion <shell>

generate shell completion scripts

shells: bash, zsh, fish

to enable bash completions (add to ~/.bashrc):
  source <(gibcert completion bash)

to enable zsh completions (add to ~/.zshrc):
  source <(gibcert completion zsh)

to enable fish completions:
  gibcert completion fish > ~/.config/fish/completions/gibcert.fish
`

const bashCompletion = `# bash completion for gibcert
_gibcert() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local commands="help version check plan apply issue renew account ca dns-persist tlsa deploy revoke delete rename list show import completion"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return
    fi

    case ${words[1]} in
    issue|deploy|revoke|delete|show)
        COMPREPLY=($(compgen -W "$(gibcert __complete certs 2>/dev/null)" -- "$cur"))
        ;;
    rename)
        case $cword in
        2) COMPREPLY=($(compgen -W "$(gibcert __complete certs 2>/dev/null)" -- "$cur")) ;;
        esac
        ;;
    account)
        case $cword in
        2) COMPREPLY=($(compgen -W "rotate-key" -- "$cur")) ;;
        3) [[ ${words[2]} == "rotate-key" ]] && COMPREPLY=($(compgen -W "$(gibcert __complete accounts 2>/dev/null)" -- "$cur")) ;;
        esac
        ;;
    ca)
        case $cword in
        2) COMPREPLY=($(compgen -W "list show export" -- "$cur")) ;;
        3) [[ ${words[2]} != "list" ]] && COMPREPLY=($(compgen -W "$(gibcert __complete cas 2>/dev/null)" -- "$cur")) ;;
        esac
        ;;
    dns-persist)
        case $cword in
        2) COMPREPLY=($(compgen -W "install check" -- "$cur")) ;;
        3) COMPREPLY=($(compgen -W "$(gibcert __complete certs 2>/dev/null)" -- "$cur")) ;;
        esac
        ;;
    tlsa)
        case $cword in
        2) COMPREPLY=($(compgen -W "reconcile" -- "$cur")) ;;
        3) COMPREPLY=($(compgen -W "$(gibcert __complete certs 2>/dev/null)" -- "$cur")) ;;
        esac
        ;;
    import)
        case $cword in
        2) COMPREPLY=($(compgen -W "acme.sh certbot dehydrated lego pem" -- "$cur")) ;;
        *) [[ ${words[2]} == @(acme.sh|certbot|dehydrated|lego) ]] && COMPREPLY=($(compgen -d -- "$cur")) ;;
        esac
        ;;
    completion)
        COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
        ;;
    help)
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        ;;
    esac
}
complete -F _gibcert gibcert
`

const zshCompletion = `#compdef gibcert
# zsh completion for gibcert

_gibcert() {
    local state line
    typeset -A opt_args

    _arguments \
        '(-c --config)'{-c,--config}'[path to config file]:config file:_files' \
        '--state-dir[path to state directory]:state dir:_files -/' \
        '--log-format[log format]:format:(text json)' \
        '--syslog[also send logs to syslog]' \
        '1: :_gibcert_commands' \
        '*:: :->args'

    case $state in
    args)
        case $words[1] in
        issue)
            _arguments \
                '--new-key[force certificate key rotation]' \
                '1: :_gibcert_certs'
            ;;
        apply)
            _arguments '--yes[approve externally visible actions]'
            ;;
		renew)
			_arguments \
				'--max-jitter[sleep up to duration before each renewal]:duration' \
				'--no-jitter[disable renewal jitter]' \
				'--verbose[print renewal activity]'
			;;
		account)
			_arguments '1: :_gibcert_account_subcmds' '*:: :->accountargs'
			case $state in
			accountargs)
				case $words[1] in
				rotate-key)
					_arguments '1: :_gibcert_accounts'
					;;
				esac
				;;
			esac
			;;
		deploy|show)
			_arguments '1: :_gibcert_certs'
			;;
        revoke)
            _arguments \
                '--reason[revocation reason]:reason:(unspecified keycompromise cacompromise affiliationchanged superseded cessationofoperation certificatehold removefromcrl privilegewithdrawn aacompromise)' \
                '--reissue[issue and deploy a replacement]' \
                '--yes[approve revocation]' \
                '1: :_gibcert_certs'
            ;;
        delete)
            _arguments \
                '--undeploy[remove last deployed files when content still matches]' \
                '--revoke[revoke before deleting local state]' \
                '--reason[revocation reason]:reason:(unspecified keycompromise cacompromise affiliationchanged superseded cessationofoperation certificatehold removefromcrl privilegewithdrawn aacompromise)' \
                '--yes[approve deletion]' \
                '1: :_gibcert_certs'
            ;;
        rename)
            _arguments \
                '1:old name:_gibcert_certs' \
                '2:new name'
            ;;
        ca)
            _arguments '1: :_gibcert_ca_subcmds' '*:: :->caargs'
            case $state in
            caargs)
                case $words[1] in
                show|export)
                    _arguments '1: :_gibcert_cas'
                    ;;
                esac
                ;;
            esac
            ;;
        dns-persist)
            _arguments '1: :_gibcert_dns_persist_subcmds' '*:: :->dpargs'
            case $state in
            dpargs)
                case $words[1] in
                install)
                    _arguments \
                        '--print[print the record without writing it]' \
                        '1: :_gibcert_certs'
                    ;;
                check)
                    _arguments '1: :_gibcert_certs'
                    ;;
                esac
                ;;
            esac
            ;;
        tlsa)
            _arguments '1: :_gibcert_tlsa_subcmds' '*:: :->tlsaargs'
            case $state in
            tlsaargs)
                case $words[1] in
                reconcile)
                    _arguments '1: :_gibcert_certs'
                    ;;
                esac
                ;;
            esac
            ;;
        import)
            _arguments '1: :_gibcert_import_sources' '*:: :->importargs'
            case $state in
            importargs)
                case $words[1] in
                acme.sh)
                    _arguments \
                        '--dry-run[print what would be imported without writing]' \
                        '--force[overwrite existing canonical state]' \
                        '--name[store a single imported certificate under this name]:name' \
                        '*--only[import only this cert]:cert name:_gibcert_certs' \
                        '1:path:_files -/'
                    ;;
                certbot)
                    _arguments \
                        '--dry-run[print what would be imported without writing]' \
                        '--force[overwrite existing canonical state]' \
                        '--name[store a single imported certificate under this name]:name' \
                        '*--only[import only this cert]:cert name:_gibcert_certs' \
                        '1:path:_files -/'
                    ;;
                dehydrated)
                    _arguments \
                        '--dry-run[print what would be imported without writing]' \
                        '--force[overwrite existing canonical state]' \
                        '--name[store a single imported certificate under this name]:name' \
                        '*--only[import only this cert]:cert name:_gibcert_certs' \
                        '1:path:_files -/'
                    ;;
                lego)
                    _arguments \
                        '--dry-run[print what would be imported without writing]' \
                        '--force[overwrite existing canonical state]' \
                        '--name[store a single imported certificate under this name]:name' \
                        '*--only[import only this cert]:cert name:_gibcert_certs' \
                        '1:path:_files -/'
                    ;;
                pem)
                    _arguments \
                        '--dry-run[print what would be imported without writing]' \
                        '--force[overwrite existing canonical state]' \
                        '--name[store imported certificate under this name]:name' \
                        '--cert[leaf certificate PEM]:file:_files' \
                        '--chain[chain certificate PEM]:file:_files' \
                        '--fullchain[fullchain PEM]:file:_files' \
                        '--key[private key PEM]:file:_files'
                    ;;
                esac
                ;;
            esac
            ;;
        completion)
            _arguments '1: :(bash zsh fish)'
            ;;
        help)
            _arguments '1: :_gibcert_commands'
            ;;
        esac
        ;;
    esac
}

_gibcert_commands() {
    local -a commands
    commands=(
        'help:show usage'
        'version:print build version information'
        'check:parse and validate the config'
        'plan:show what apply would change'
        'apply:reconcile state with config'
        'issue:issue one certificate'
        'renew:renew due certificates and deploy changed material'
        'account:manage ACME accounts'
        'ca:list, show, or export CA profiles'
        'dns-persist:manage dns-persist-01 standing records'
        'tlsa:manage DANE TLSA records'
        'deploy:deploy stored certificate material to configured targets'
        'revoke:revoke a stored certificate at the CA'
        'delete:remove local certificate state, optionally undeploying'
        'rename:rename stored certificate state'
        'list:list configured certificates and local status'
        'show:show certificate config and local status'
        'import:import certificate material from another client or PEM files'
        'completion:generate shell completion scripts'
    )
    _describe 'command' commands
}

_gibcert_certs() {
    local -a certs
    certs=(${(f)"$(gibcert __complete certs 2>/dev/null)"})
    _describe 'certificate' certs
}

_gibcert_cas() {
    local -a cas
    cas=(${(f)"$(gibcert __complete cas 2>/dev/null)"})
    _describe 'CA' cas
}

_gibcert_accounts() {
    local -a accounts
    accounts=(${(f)"$(gibcert __complete accounts 2>/dev/null)"})
    _describe 'account' accounts
}

_gibcert_ca_subcmds() {
    local -a subcmds
    subcmds=('list:list CA profiles' 'show:show CA details' 'export:export CA certificate')
    _describe 'subcommand' subcmds
}

_gibcert_account_subcmds() {
    local -a subcmds
    subcmds=('rotate-key:rotate an ACME account key')
    _describe 'subcommand' subcmds
}

_gibcert_dns_persist_subcmds() {
    local -a subcmds
    subcmds=('install:install standing DNS record' 'check:check standing DNS record')
    _describe 'subcommand' subcmds
}

_gibcert_tlsa_subcmds() {
    local -a subcmds
    subcmds=('reconcile:reconcile stored certificate TLSA records')
    _describe 'subcommand' subcmds
}

_gibcert_import_sources() {
    _describe 'source' '(acme.sh:import from acme.sh certbot:import from certbot dehydrated:import from dehydrated lego:import from lego pem:import explicit PEM files)'
}

_gibcert
`

const fishCompletion = `# fish completion for gibcert

function __gibcert_no_subcommand
    set -l commands help version check plan apply issue renew account ca dns-persist tlsa deploy revoke delete rename list show import completion
    not __fish_seen_subcommand_from $commands
end

function __gibcert_certs
    gibcert __complete certs 2>/dev/null
end

function __gibcert_cas
    gibcert __complete cas 2>/dev/null
end

# disable file completion by default
complete -c gibcert -f

# global flags
complete -c gibcert -l config -s c -d 'path to config file' -r
complete -c gibcert -l state-dir -d 'path to state directory' -r
complete -c gibcert -l log-format -d 'log format' -a 'text json' -r
complete -c gibcert -l syslog -d 'also send logs to syslog'

# top-level commands
complete -c gibcert -n __gibcert_no_subcommand -a help -d 'show usage'
complete -c gibcert -n __gibcert_no_subcommand -a version -d 'print build version information'
complete -c gibcert -n __gibcert_no_subcommand -a check -d 'parse and validate the config'
complete -c gibcert -n __gibcert_no_subcommand -a plan -d 'show what apply would change'
complete -c gibcert -n __gibcert_no_subcommand -a apply -d 'reconcile state with config'
complete -c gibcert -n __gibcert_no_subcommand -a issue -d 'issue one certificate'
complete -c gibcert -n __gibcert_no_subcommand -a renew -d 'renew due certificates and deploy changed material'
complete -c gibcert -n __gibcert_no_subcommand -a account -d 'manage ACME accounts'
complete -c gibcert -n __gibcert_no_subcommand -a ca -d 'list, show, or export CA profiles'
complete -c gibcert -n __gibcert_no_subcommand -a dns-persist -d 'manage dns-persist-01 standing records'
complete -c gibcert -n __gibcert_no_subcommand -a tlsa -d 'manage DANE TLSA records'
complete -c gibcert -n __gibcert_no_subcommand -a deploy -d 'deploy stored certificate material'
complete -c gibcert -n __gibcert_no_subcommand -a revoke -d 'revoke a stored certificate at the CA'
complete -c gibcert -n __gibcert_no_subcommand -a delete -d 'remove local certificate state'
complete -c gibcert -n __gibcert_no_subcommand -a rename -d 'rename stored certificate state'
complete -c gibcert -n __gibcert_no_subcommand -a list -d 'list configured certificates and local status'
complete -c gibcert -n __gibcert_no_subcommand -a show -d 'show certificate config and local status'
complete -c gibcert -n __gibcert_no_subcommand -a import -d 'import certificate material from another client or PEM files'
complete -c gibcert -n __gibcert_no_subcommand -a completion -d 'generate shell completion scripts'

# apply flags
complete -c gibcert -n '__fish_seen_subcommand_from apply' -l yes -d 'approve externally visible actions'

# issue flags and cert arg
complete -c gibcert -n '__fish_seen_subcommand_from issue' -l new-key -d 'force certificate key rotation'
complete -c gibcert -n '__fish_seen_subcommand_from issue' -a '(__gibcert_certs)'

# renew flags
complete -c gibcert -n '__fish_seen_subcommand_from renew' -l max-jitter -d 'sleep up to duration before each renewal' -r
complete -c gibcert -n '__fish_seen_subcommand_from renew' -l no-jitter -d 'disable renewal jitter'
complete -c gibcert -n '__fish_seen_subcommand_from renew' -l verbose -d 'print renewal activity'

# account subcommands and account name arg
complete -c gibcert -n '__fish_seen_subcommand_from account; and not __fish_seen_subcommand_from rotate-key' -a rotate-key -d 'rotate an ACME account key'
complete -c gibcert -n '__fish_seen_subcommand_from account; and __fish_seen_subcommand_from rotate-key' -a '(gibcert __complete accounts 2>/dev/null)'

# ca subcommands and CA name arg
complete -c gibcert -n '__fish_seen_subcommand_from ca; and not __fish_seen_subcommand_from list show export' -a list -d 'list CA profiles'
complete -c gibcert -n '__fish_seen_subcommand_from ca; and not __fish_seen_subcommand_from list show export' -a show -d 'show CA details'
complete -c gibcert -n '__fish_seen_subcommand_from ca; and not __fish_seen_subcommand_from list show export' -a export -d 'export CA certificate'
complete -c gibcert -n '__fish_seen_subcommand_from ca; and __fish_seen_subcommand_from show export' -a '(__gibcert_cas)'

# dns-persist subcommands and cert arg
complete -c gibcert -n '__fish_seen_subcommand_from dns-persist; and not __fish_seen_subcommand_from install check' -a install -d 'install standing DNS record'
complete -c gibcert -n '__fish_seen_subcommand_from dns-persist; and not __fish_seen_subcommand_from install check' -a check -d 'check standing DNS record'
complete -c gibcert -n '__fish_seen_subcommand_from dns-persist; and __fish_seen_subcommand_from install' -l print -d 'print the record without writing it'
complete -c gibcert -n '__fish_seen_subcommand_from dns-persist; and __fish_seen_subcommand_from install check' -a '(__gibcert_certs)'

# tlsa subcommands and cert arg
complete -c gibcert -n '__fish_seen_subcommand_from tlsa; and not __fish_seen_subcommand_from reconcile' -a reconcile -d 'reconcile stored certificate TLSA records'
complete -c gibcert -n '__fish_seen_subcommand_from tlsa; and __fish_seen_subcommand_from reconcile' -a '(__gibcert_certs)'

# commands that take a cert name
complete -c gibcert -n '__fish_seen_subcommand_from deploy show' -a '(__gibcert_certs)'

# revoke flags and cert arg
complete -c gibcert -n '__fish_seen_subcommand_from revoke' -l reason -d 'revocation reason' -r
complete -c gibcert -n '__fish_seen_subcommand_from revoke' -l reissue -d 'issue and deploy a replacement'
complete -c gibcert -n '__fish_seen_subcommand_from revoke' -l yes -d 'approve revocation'
complete -c gibcert -n '__fish_seen_subcommand_from revoke' -a '(__gibcert_certs)'

# rename: old cert name arg
complete -c gibcert -n '__fish_seen_subcommand_from rename' -a '(__gibcert_certs)'

# delete flags and cert arg
complete -c gibcert -n '__fish_seen_subcommand_from delete' -l undeploy -d 'remove last deployed files when content still matches'
complete -c gibcert -n '__fish_seen_subcommand_from delete' -l revoke -d 'revoke before deleting local state'
complete -c gibcert -n '__fish_seen_subcommand_from delete' -l reason -d 'revocation reason' -r
complete -c gibcert -n '__fish_seen_subcommand_from delete' -l yes -d 'approve deletion'
complete -c gibcert -n '__fish_seen_subcommand_from delete' -a '(__gibcert_certs)'

# import source and path
complete -c gibcert -n '__fish_seen_subcommand_from import; and not __fish_seen_subcommand_from acme.sh certbot dehydrated lego pem' -a 'acme.sh' -d 'import from acme.sh'
complete -c gibcert -n '__fish_seen_subcommand_from import; and not __fish_seen_subcommand_from acme.sh certbot dehydrated lego pem' -a 'certbot' -d 'import from certbot'
complete -c gibcert -n '__fish_seen_subcommand_from import; and not __fish_seen_subcommand_from acme.sh certbot dehydrated lego pem' -a 'dehydrated' -d 'import from dehydrated'
complete -c gibcert -n '__fish_seen_subcommand_from import; and not __fish_seen_subcommand_from acme.sh certbot dehydrated lego pem' -a 'lego' -d 'import from lego'
complete -c gibcert -n '__fish_seen_subcommand_from import; and not __fish_seen_subcommand_from acme.sh certbot dehydrated lego pem' -a 'pem' -d 'import explicit PEM files'
complete -c gibcert -n '__fish_seen_subcommand_from import' -l dry-run -d 'print what would be imported without writing'
complete -c gibcert -n '__fish_seen_subcommand_from import' -l force -d 'overwrite existing canonical state'
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from acme.sh' -l only -d 'import only this cert' -r
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from certbot' -l only -d 'import only this cert' -r
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from dehydrated' -l only -d 'import only this cert' -r
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from lego' -l only -d 'import only this cert' -r
complete -c gibcert -n '__fish_seen_subcommand_from import' -l name -d 'store imported cert under this name' -r
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from pem' -l cert -d 'leaf certificate PEM' -r -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from pem' -l chain -d 'chain certificate PEM' -r -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from pem' -l fullchain -d 'fullchain PEM' -r -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from pem' -l key -d 'private key PEM' -r -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from acme.sh' -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from certbot' -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from dehydrated' -F
complete -c gibcert -n '__fish_seen_subcommand_from import; and __fish_seen_subcommand_from lego' -F

# completion shells
complete -c gibcert -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'

# help subcommands
complete -c gibcert -n '__fish_seen_subcommand_from help' -a 'help version check plan apply issue renew account ca dns-persist deploy revoke delete rename list show import completion'
`

func cmdCompletion(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, completionUsage)
		return 2
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	default:
		fmt.Fprintf(os.Stderr, "gibcert: unknown shell %q (supported: bash, zsh, fish)\n", args[0])
		return 2
	}
	return 0
}

func cmdInternalComplete(p *paths.Paths, args []string) int {
	if len(args) == 0 {
		return 0
	}
	switch args[0] {
	case "certs":
		seen := make(map[string]struct{})
		cfg, _ := config.Load(p.Config)
		if cfg != nil {
			for _, cert := range cfg.Certificates {
				fmt.Println(cert.Name)
				seen[cert.Name] = struct{}{}
			}
		}
		store := storage.New(p.State)
		if storageNames, err := store.ListCertNames(); err == nil {
			for _, name := range storageNames {
				if _, ok := seen[name]; !ok {
					fmt.Println(name)
				}
			}
		}
	case "cas":
		cfg, err := config.Load(p.Config)
		if err != nil {
			return 0
		}
		cas := config.CAProfiles(cfg.CAs)
		names := make([]string, 0, len(cas))
		for name := range cas {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
	case "accounts":
		cfg, err := config.Load(p.Config)
		if err != nil {
			return 0
		}
		seen := map[string]bool{}
		var names []string
		for _, account := range cfg.Accounts {
			names = append(names, account.Name)
			seen[account.Name] = true
		}
		for _, ca := range config.CAProfiles(cfg.CAs) {
			if ca.Type != "" && ca.Type != "acme" {
				continue
			}
			name := config.ImplicitACMEAccountName(ca.Name)
			if !seen[name] {
				names = append(names, name)
				seen[name] = true
			}
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Println(name)
		}
	}
	return 0
}
