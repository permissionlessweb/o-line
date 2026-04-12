#!/bin/bash
# Mock pfSsh.php — interprets the PHP-like commands that pfsense-bootstrap.sh sends.
# Operates on a JSON config file at /conf/config.json using jq.
#
# Supports the subset of PHP used by pfsense-bootstrap.sh:
#   parse_config(true);  /  write_config("...");  /  filter_configure();
#   echo "PREFIX" . $config["x"]["y"];
#   $config["x"]["y"] = "val";
#   $config["x"]["y"][] = array( "k" => "v", ... );
#   unset($config["x"]["y"]);
#   isset / is_array / foreach / if-else / strpos
#   $var = 0; / $var++; / $keep = array(); / $keep[] = $r;
#   exec / exit

CONFIG_FILE="/conf/config.json"

# ── State ────────────────────────────────────────────────────────────────────

declare -A VARS
KEEP_ARRAY="[]"
CURRENT_R=""
FOREACH_ITEMS=""
FOREACH_COUNT=0
SKIP_DEPTH=0
IF_RESULT=""
IN_FOREACH_COLLECT=0
BRACE_DEPTH=0
declare -a FOREACH_BODY=()

# ── JSON helpers ─────────────────────────────────────────────────────────────

cfg_read() { jq -r "$1" "$CONFIG_FILE" 2>/dev/null; }

cfg_write() {
    # Usage: cfg_write 'jq_expr'
    #    or: cfg_write 'jq_expr' varname jsonvalue  (adds --argjson varname jsonvalue)
    local tmp; tmp=$(mktemp)
    if [[ $# -eq 1 ]]; then
        jq "$1" "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    elif [[ $# -eq 3 ]]; then
        jq --argjson "$2" "$3" "$1" "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    else
        rm -f "$tmp"
    fi
}

# Convert $config["a"]["b"]["c"] → .a.b.c
php_path_to_jq() {
    echo "$1" | sed -E 's/\$config//; s/\["([^"]+)"\]/.\1/g'
}

# ── Foreach executor ────────────────────────────────────────────────────────

execute_foreach() {
    local i=0
    while [[ $i -lt $FOREACH_COUNT ]]; do
        CURRENT_R=$(echo "$FOREACH_ITEMS" | jq ".[$i]")
        for bline in "${FOREACH_BODY[@]}"; do
            process_line "$bline"
        done
        i=$((i + 1))
    done
    CURRENT_R=""
}

# ── Multi-line array(...) → JSON object ─────────────────────────────────────
# Reads lines after `$config["x"][] = array(` until `);`

collect_array_append() {
    local jq_path="$1"
    local buf=""

    while IFS= read -r aline || [[ -n "$aline" ]]; do
        aline="$(echo "$aline" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

        # End of array
        [[ "$aline" =~ ^\)\; ]] && break

        # "key" => array("k1" => "v1", "k2" => "v2"),
        if [[ "$aline" =~ ^\"([^\"]+)\"[[:space:]]*\=\>[[:space:]]*array\( ]]; then
            local akey="${BASH_REMATCH[1]}"
            local inner
            inner=$(echo "$aline" | sed -E 's/.*array\((.*)\),?$/\1/' | sed 's/)$//')
            # Parse comma-separated "k" => "v" pairs
            local inner_buf=""
            while IFS= read -r pair; do
                pair=$(echo "$pair" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
                [[ -z "$pair" ]] && continue
                local pk pv
                pk=$(echo "$pair" | sed -E 's/^"([^"]+)".*/\1/')
                pv=$(echo "$pair" | sed -E 's/.*=>[[:space:]]*"([^"]*)".*/\1/')
                inner_buf="$inner_buf \"$pk\": \"$pv\","
            done <<< "$(echo "$inner" | tr ',' '\n')"
            buf="$buf \"$akey\": {${inner_buf%,}},"
        # "key" => "value",
        elif [[ "$aline" =~ ^\"([^\"]+)\"[[:space:]]*\=\> ]]; then
            local akey="${BASH_REMATCH[1]}"
            local aval
            aval=$(echo "$aline" | sed -E 's/.*=>[[:space:]]*"([^"]*)"[,[:space:]]*/\1/')
            buf="$buf \"$akey\": \"$aval\","
        fi
    done

    local json_obj="{${buf%,}}"
    cfg_write "${jq_path} += [\$item]" item "$json_obj"
}

# ── Line processor ──────────────────────────────────────────────────────────

process_line() {
    local line="$1"
    line="$(echo "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -z "$line" ]] && return 0

    # ── Collecting foreach body ──
    if [[ "$IN_FOREACH_COLLECT" -eq 1 ]]; then
        local opens closes
        opens=$(echo "$line" | tr -cd '{' | wc -c | tr -d ' ')
        closes=$(echo "$line" | tr -cd '}' | wc -c | tr -d ' ')
        BRACE_DEPTH=$((BRACE_DEPTH + opens - closes))
        if [[ "$BRACE_DEPTH" -le 0 ]]; then
            IN_FOREACH_COLLECT=0
            execute_foreach
            return 0
        fi
        FOREACH_BODY+=("$line")
        return 0
    fi

    # ── Skip depth (inside skipped if/else) ──
    if [[ "$SKIP_DEPTH" -gt 0 ]]; then
        if [[ "$line" =~ ^\}[[:space:]]*else[[:space:]]*\{ ]]; then
            [[ "$SKIP_DEPTH" -eq 1 ]] && { SKIP_DEPTH=0; return 0; }
        elif [[ "$line" =~ ^\}[[:space:]]*$ ]]; then
            SKIP_DEPTH=$((SKIP_DEPTH - 1))
            return 0
        fi
        [[ "$line" =~ \{[[:space:]]*$ ]] && SKIP_DEPTH=$((SKIP_DEPTH + 1))
        return 0
    fi

    # ── Closing brace ──
    [[ "$line" =~ ^\}[[:space:]]*$ ]] && return 0

    # ── } else { (multi-line) ──
    if [[ "$line" =~ ^\}[[:space:]]*else[[:space:]]*\{[[:space:]]*$ ]]; then
        SKIP_DEPTH=1
        return 0
    fi

    # ── else { body; } (inline, or } else { body; }) ──
    if [[ "$line" =~ else[[:space:]]*\{(.+)\} ]]; then
        if [[ "$IF_RESULT" == "false" ]]; then
            local body="${BASH_REMATCH[1]}"
            IFS=';' read -ra stmts <<< "$body"
            for stmt in "${stmts[@]}"; do
                stmt="$(echo "$stmt" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
                [[ -n "$stmt" ]] && process_line "${stmt};"
            done
        fi
        return 0
    fi

    # ── exec / exit ──
    [[ "$line" == "exec" || "$line" == "exit" ]] && exit 0

    # ── No-ops ──
    [[ "$line" == "parse_config(true);" ]] && return 0
    [[ "$line" == "filter_configure();" ]] && {
        if [[ "$(id -u)" == "0" ]]; then
            /usr/local/sbin/apply_firewall_rules.sh 2>/dev/null || true
        else
            sudo /usr/local/sbin/apply_firewall_rules.sh 2>/dev/null || true
        fi
        return 0
    }
    [[ "$line" =~ ^write_config\( ]] && return 0

    # ── echo "PREFIX" . $config["x"]["y"]; ──
    if [[ "$line" =~ ^echo[[:space:]]+\" ]] && [[ "$line" =~ \$config\[ ]]; then
        local prefix val_path jq_path val
        prefix=$(echo "$line" | sed -E 's/^echo[[:space:]]+"([^"]*)".*/\1/')
        val_path=$(echo "$line" | sed -E 's/.*(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$val_path")
        val=$(cfg_read "$jq_path")
        echo "${prefix}${val}"
        return 0
    fi

    # ── echo "...\n"; (simple print) ──
    if [[ "$line" =~ ^echo[[:space:]]+\" ]]; then
        local msg
        msg=$(echo "$line" | sed -E 's/^echo[[:space:]]+"(.*)";[[:space:]]*$/\1/')
        # Expand $removed
        [[ -n "${VARS[removed]:-}" ]] && msg="${msg//\$removed/${VARS[removed]}}"
        msg="${msg//\\n/}"
        echo "$msg"
        return 0
    fi

    # ── $var = 0; (init numeric) ──
    if [[ "$line" =~ ^\$([a-z_]+)[[:space:]]*=[[:space:]]*([0-9]+)\; ]]; then
        VARS[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
        return 0
    fi

    # ── $var++; ──
    if [[ "$line" =~ ^\$([a-z_]+)\+\+\; ]]; then
        local vn="${BASH_REMATCH[1]}"
        VARS[$vn]=$(( ${VARS[$vn]:-0} + 1 ))
        return 0
    fi

    # ── $keep = array(); ──
    [[ "$line" =~ ^\$keep[[:space:]]*=[[:space:]]*array\(\)\; ]] && { KEEP_ARRAY="[]"; return 0; }

    # ── $keep[] = $r; ──
    if [[ "$line" =~ ^\$keep\[\][[:space:]]*=[[:space:]]*\$r\; ]]; then
        KEEP_ARRAY=$(echo "$KEEP_ARRAY" | jq --argjson r "$CURRENT_R" '. + [$r]')
        return 0
    fi

    # ── $config["x"]["y"] = $keep; ──
    if [[ "$line" =~ ^\$config ]] && [[ "$line" =~ =\ *\$keep\; ]]; then
        local path_part jq_path
        path_part=$(echo "$line" | sed -E 's/(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        cfg_write "${jq_path} = \$keep" keep "$KEEP_ARRAY"
        return 0
    fi

    # ── unset($config["x"]["y"]); ──
    if [[ "$line" =~ ^unset\(\$config ]]; then
        local path_part jq_path
        path_part=$(echo "$line" | sed -E 's/^unset\((\$config(\["[^"]+"\])+)\);/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        cfg_write "del(${jq_path})"
        return 0
    fi

    # ── if (is_array($config[...])) { ──
    if [[ "$line" =~ ^if.*is_array\(\$config ]]; then
        local path_part jq_path vtype
        path_part=$(echo "$line" | sed -E 's/.*(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        vtype=$(cfg_read "${jq_path} | type")
        if [[ "$vtype" == "array" || "$vtype" == "object" ]]; then
            IF_RESULT="true"
        else
            SKIP_DEPTH=1; IF_RESULT="false"
        fi
        return 0
    fi

    # ── if (!is_array($config[...])) { ──
    if [[ "$line" =~ ^if.*\!is_array\(\$config ]]; then
        local path_part jq_path vtype
        path_part=$(echo "$line" | sed -E 's/.*(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        vtype=$(cfg_read "${jq_path} | type")
        if [[ "$vtype" != "array" ]]; then
            IF_RESULT="true"
        else
            SKIP_DEPTH=1; IF_RESULT="false"
        fi
        return 0
    fi

    # ── if (isset($r["key"]) && strpos(...)) { body; } ──  (foreach body, inline)
    if [[ "$line" =~ ^if.*isset\(\$r\[ ]] && [[ "$line" =~ strpos ]]; then
        local key prefix r_val
        key=$(echo "$line" | sed -E 's/.*isset\(\$r\["([^"]+)"\]\).*/\1/')
        prefix=$(echo "$line" | sed -E 's/.*strpos\(\$r\["[^"]+"\],[[:space:]]*"([^"]+)"\).*/\1/')
        r_val=$(echo "$CURRENT_R" | jq -r ".${key} // empty")
        if [[ -n "$r_val" ]] && [[ "$r_val" == "${prefix}"* ]]; then
            IF_RESULT="true"
            # Handle inline body: if (...) { stmt; stmt; }
            if [[ "$line" =~ \{(.+)\}[[:space:]]*$ ]]; then
                local body="${BASH_REMATCH[1]}"
                # Split on ; and process each statement
                IFS=';' read -ra stmts <<< "$body"
                for stmt in "${stmts[@]}"; do
                    stmt="$(echo "$stmt" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
                    [[ -n "$stmt" ]] && process_line "${stmt};"
                done
            fi
        else
            IF_RESULT="false"
            # Check for inline else on the NEXT line — no skip depth for inline
        fi
        return 0
    fi

    # ── if (isset($config[...])) { ──
    if [[ "$line" =~ ^if.*isset\(\$config ]]; then
        local path_part jq_path val
        path_part=$(echo "$line" | sed -E 's/.*(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        val=$(cfg_read "$jq_path")
        if [[ -n "$val" && "$val" != "null" ]]; then
            IF_RESULT="true"
        else
            SKIP_DEPTH=1; IF_RESULT="false"
        fi
        return 0
    fi

    # ── if ($var == N) { ──
    if [[ "$line" =~ ^if.*\$([a-z_]+)[[:space:]]*==[[:space:]]*([0-9]+)\) ]]; then
        local vn="${BASH_REMATCH[1]}" thresh="${BASH_REMATCH[2]}"
        if [[ ${VARS[$vn]:-0} -eq $thresh ]]; then
            IF_RESULT="true"
        else
            SKIP_DEPTH=1; IF_RESULT="false"
        fi
        return 0
    fi

    # ── if ($var > N) { ──
    if [[ "$line" =~ ^if.*\$([a-z_]+).*\>.*([0-9]+)\) ]]; then
        local vn="${BASH_REMATCH[1]}" thresh="${BASH_REMATCH[2]}"
        if [[ ${VARS[$vn]:-0} -gt $thresh ]]; then
            IF_RESULT="true"
        else
            SKIP_DEPTH=1; IF_RESULT="false"
        fi
        return 0
    fi

    # ── foreach ($config["x"]["y"] as $r) { ──
    if [[ "$line" =~ ^foreach.*\$config ]]; then
        local path_part jq_path
        path_part=$(echo "$line" | sed -E 's/.*(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        FOREACH_ITEMS=$(cfg_read "$jq_path")
        FOREACH_COUNT=$(echo "$FOREACH_ITEMS" | jq 'length')
        IN_FOREACH_COLLECT=1
        BRACE_DEPTH=1
        FOREACH_BODY=()
        return 0
    fi

    # ── $config["x"][] = array( ... ); (multi-line array append) ──
    if [[ "$line" =~ ^\$config.*\[\][[:space:]]*=[[:space:]]*array\( ]]; then
        local path_part jq_path
        path_part=$(echo "$line" | sed -E 's/(\$config(\["[^"]+"\])+)\[\].*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        collect_array_append "$jq_path"
        return 0
    fi

    # ── $config["x"]["y"] = "val"; (scalar assignment) ──
    if [[ "$line" =~ ^\$config.*=[[:space:]]*\" ]]; then
        local path_part jq_path val
        path_part=$(echo "$line" | sed -E 's/(\$config(\["[^"]+"\])+).*/\1/')
        jq_path=$(php_path_to_jq "$path_part")
        val=$(echo "$line" | sed -E 's/.*=[[:space:]]*"([^"]*)";/\1/')
        cfg_write "${jq_path} = \"${val}\""
        return 0
    fi

    # ── Unknown — ignore ──
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────────────

while IFS= read -r line || [[ -n "$line" ]]; do
    process_line "$line"
done
