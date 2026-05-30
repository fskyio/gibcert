# fish completion for gibcert

function __gibcert_no_subcommand
    set -l commands help version check plan apply issue renew account ca dns-persist deploy revoke delete rename list show import completion
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
