# bash completion for gibcert
_gibcert() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local commands="help version check plan apply issue renew account ca dns-persist deploy revoke delete rename list show import completion"

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
