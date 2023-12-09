#!/bin/bash

# Function to generate a random password
generate_password() {
    local length=$1
    local use_special_chars=$2

    local char_set="A-Za-z0-9"
    [[ $use_special_chars -eq 1 ]] && char_set+="!@#$%&"

    password=$(head /dev/urandom | tr -dc "$char_set" | head -c$length)
    echo "$password"
}

# Function to check password strength
check_strength() {
    local password=$1
    local length=${#password}
    local has_lowercase=$(echo "$password" | grep -q [a-z] && echo "1" || echo "0")
    local has_uppercase=$(echo "$password" | grep -q [A-Z] && echo "1" || echo "0")
    local has_digit=$(echo "$password" | grep -q [0-9] && echo "1" || echo "0")
    local has_special=$(echo "$password" | grep -q '[!@#$%&]' && echo "1" || echo "0")

    local strength=0
    ((strength += length >= 8 ? 1 : 0))
    ((strength += has_lowercase))
    ((strength += has_uppercase))
    ((strength += has_digit))
    ((strength += has_special))

    echo "Password Strength: $strength/5"
}

# Function to trace password
password_tracer() {
    local username=$1
    if ! grep -q "^${username}:" /etc/passwd; then
        echo "User $username not found"
        exit 1
    fi

    local password_line=$(grep "^${username}:" /etc/shadow)
    local password_fields=($(echo "$password_line" | cut -d: -f2))
    local encrypted_password=${password_fields[0]}
    echo "Encrypted password for user $username is: $encrypted_password"
}

# Function to update user password
update_password() {
    local username=$1
    local new_password=$2
    sudo passwd $username <<< "$new_password"$'\n'"$new_password" &>/dev/null
    echo "Password updated successfully for user $username"
}

# Main Menu
main_menu() {
    echo "Password Generator, Strength Checker & User Password Tracer"
    read -p "Enter 1 to generate password, 2 to check password strength, 3 to trace user password, or 4 to update user password: " option
    
    case $option in
        1)
            read -p "Enter the length of the password to generate: " pass_length
            read -p "Do you want to include special characters? (y/n): " include_special
            use_special_chars=0
            [[ $include_special = "y" ]] && use_special_chars=1
            generated_password=$(generate_password $pass_length $use_special_chars)
            echo "Generated Password: $generated_password";;
        2)
            read -p "Enter the password to check strength: " password
            check_strength "$password";;
        3)
            read -p "Enter the username to trace password: " username
            password_tracer "$username";;
        4)
            read -p "Enter the username to update password: " username
            read -s -p "Enter the new password: " new_password
            update_password "$username" "$new_password";;
        *)
            echo "Invalid option";;
    esac
}

# Execute the script
main_menu

