# sreg bash completion

_secrg_commands() {
    echo "init login get set delete list audit status security export import version help"
}

_secrg_init_options() {
    echo "--force --help"
}

_secrg_login_options() {
    echo "--help"
}

_secrg_get_options() {
    echo "--decrypt --no-decrypt --json --help"
}

_secrg_set_options() {
    echo "--type --encrypt --help"
}

_secrg_delete_options() {
    echo "--recursive --help"
}

_secrg_list_options() {
    echo "--recursive --json --help"
}

_secrg_audit_options() {
    echo "--user --key --action --since --limit --json --help"
}

_secrg_status_options() {
    echo "--json --help"
}

_secrg_security_options() {
    echo "check audit --help"
}

_secrg_export_options() {
    echo "--output --encrypt --help"
}

_secrg_import_options() {
    echo "--decrypt --force --help"
}

_secrg() {
    local cur prev words cword
    _init_completion || return

    local command commands
    commands=$(_secrg_commands)

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return 0
    fi

    command="${words[1]}"

    # Handle subcommands
    if [[ "$command" == "security" && $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "check audit" -- "$cur"))
        return 0
    fi

    # Get options for command
    local options
    case "$command" in
        init)       options=$(_secrg_init_options) ;;
        login)      options=$(_secrg_login_options) ;;
        get)        options=$(_secrg_get_options) ;;
        set)        options=$(_secrg_set_options) ;;
        delete)     options=$(_secrg_delete_options) ;;
        list)       options=$(_secrg_list_options) ;;
        audit)      options=$(_secrg_audit_options) ;;
        status)     options=$(_secrg_status_options) ;;
        security)   options=$(_secrg_security_options) ;;
        export)     options=$(_secrg_export_options) ;;
        import)     options=$(_secrg_import_options) ;;
        *)          options="" ;;
    esac

    COMPREPLY=($(compgen -W "$options" -- "$cur"))
    __ltrim_colon_completions "$cur"
} && complete -F _secrg sreg

# Local variables:
# mode: shell-script
# sh-basic-offset: 4
# sh-indent-comment: t
# indent-tabs-mode: nil
# End:
# ex: ts=4 sw=4 et filetype=sh
