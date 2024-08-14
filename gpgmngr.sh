#!/bin/bash

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # Sin color

# Function to display usage information
usage() {
    echo -e "${CYAN}Usage: $0 [OPTION]${NC}"
    echo -e "${MAGENTA}Manage GPG functionalities${NC}"
    echo ""
    echo -e "${GREEN}Options:${NC}"
    echo -e "  ${YELLOW}-h, --help${NC}     ${BLUE}Display this help message${NC}"
    echo -e "  ${YELLOW}-v, --version${NC}  ${BLUE}Display version information${NC}"
}

# Function to display version information
version() {
    echo -e "${CYAN}gpgmngr (GPG Manager) 1.0.0${NC}"
}

# Function to check if GPG is installed
check_gpg_installed() {
    if ! command -v gpg &> /dev/null; then
        echo -e "${RED}GPG is not installed. Do you want to install it? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            sudo apt-get update
            sudo apt-get install gnupg
        else
            echo -e "${RED}GPG is necessary for this program. Exiting.${NC}"
            exit 1
        fi
    else
        version=$(gpg --version | head -n 1)
        echo -e "${GREEN}GPG is installed. Version: $version${NC}"
    fi
}

# Function to display the main menu
show_main_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${NC}          gpgmngr (GPG Manager)${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN} 1.${NC} ${NC}Key Management${NC}"
    echo -e "${GREEN} 2.${NC} ${NC}Encryption and Decryption${NC}"
    echo -e "${GREEN} 3.${NC} ${NC}Signing and Verification${NC}"
    echo -e "${GREEN} 4.${NC} ${NC}Key Trade Operations${NC}"
    echo -e "${GREEN} 5.${NC} ${NC}Backup and Restore${NC}"
    echo -e "${GREEN} 6.${NC} ${NC}Miscellaneous${NC}"
    echo -e "${GREEN} 0.${NC} ${NC}Exit${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}Please select an option:${NC}"
    echo -n "> "
}

# Function to display the key management submenu
show_key_management_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${NC}          Main > Key Management${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN} 1.${NC} ${NC}Create new key${NC}"
    echo -e "${GREEN} 2.${NC} ${NC}List keys${NC}"
    echo -e "${GREEN} 3.${NC} ${NC}Edit key${NC}"
    echo -e "${GREEN} 4.${NC} ${NC}Delete key${NC}"
    echo -e "${GREEN} 5.${NC} ${NC}Revoke key${NC}"
    echo -e "${GREEN} 6.${NC} ${NC}Generate revocation certificate${NC}"
    echo -e "${GREEN} 7.${NC} ${NC}Manage subkeys${NC}"
    echo -e "${GREEN} 8.${NC} ${NC}Change passphrase${NC}"
    echo -e "${GREEN} 9.${NC} ${NC}Modify key expiration${NC}"
    echo -e "${GREEN}10.${NC} ${NC}Clean keyring${NC}"
    echo -e "${GREEN} 0.${NC} ${NC}Back to main menu${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}Please select an option:${NC}"
    echo -n "> "
}

# Function to display the encryption and decryption submenu
show_encryption_decryption_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${NC}    Main > Encryption and Decryption${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN} 1.${NC} ${NC}Encrypt document${NC}"
    echo -e "${GREEN} 2.${NC} ${NC}Decrypt document${NC}"
    echo -e "${GREEN} 3.${NC} ${NC}Symmetric encryption${NC}"
    echo -e "${GREEN} 0.${NC} ${NC}Back to main menu${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}Please select an option:${NC}"
    echo -n "> "
}

# Function to display the signing and verification submenu
show_signing_verification_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${NC}    Main > Signing and Verification    ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN} 1.${NC} ${NC}Sign document${NC}"
    echo -e "${GREEN} 2.${NC} ${NC}Verify signature${NC}"
    echo -e "${GREEN} 3.${NC} ${NC}Sign key${NC}"
    echo -e "${GREEN} 4.${NC} ${NC}Verify file integrity${NC}"
    echo -e "${GREEN} 0.${NC} ${NC}Back to main menu${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}Please select an option:${NC}"
    echo -n "> "
}


# Function to display the key server operations submenu
show_key_server_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${NC}      Main > Key Trade Operations${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN} 1.${NC} ${NC}Import key from file${NC}"
    echo -e "${GREEN} 2.${NC} ${NC}Import key from keyserver${NC}"
    echo -e "${GREEN} 3.${NC} ${NC}Export public key${NC}"
    echo -e "${GREEN} 4.${NC} ${NC}Export private key${NC}"
    echo -e "${GREEN} 5.${NC} ${NC}Upload key to keyserver${NC}"
    echo -e "${GREEN} 6.${NC} ${NC}Update key on keyserver${NC}"
    echo -e "${GREEN} 0.${NC} ${NC}Back to main menu${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}Please select an option:${NC}"
    echo -n "> "
}

# Function to display the miscellaneous menu
show_miscellaneous_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${NC}    Main > Miscellaneous Operations${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN} 1.${NC} ${NC}Show GPG config info${NC}"
    echo -e "${GREEN} 2.${NC} ${NC}Show key fingerprint${NC}"
    echo -e "${GREEN} 0.${NC} ${NC}Back to main menu${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}Please select an option:${NC}"
    echo -n "> "
}


# Function to handle main menu selection
handle_main_selection() {
    case $1 in
        1) key_management_menu ;;
        2) encryption_decryption_menu ;;
        3) signing_verification_menu ;;
        4) key_server_menu ;;
        5) backup_restore ;;
        6) miscellaneous_menu ;;
        0) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
}

# Function to handle key management menu selection
key_management_menu() {
    while true; do
        show_key_management_menu
        echo -n "> "
        read -r choice
        case $choice in
            1) create_key ;;
            2) list_keys ;;
            3) edit_key ;;
            4) delete_key ;;
            5) revoke_key ;;
            6) generate_revocation_certificate ;;
            7) manage_subkeys ;;
            8) change_passphrase ;;
            9) modify_key_expiration ;;
            10) clean_keyring ;;
            0) return ;;
            *) echo "Invalid option" ;;
        esac
    done
}

# Function to handle encryption and decryption menu selection
encryption_decryption_menu() {
    while true; do
        show_encryption_decryption_menu
        echo -n "> "
        read -r choice
        case $choice in
            1) encrypt_document ;;
            2) decrypt_document ;;
            3) symmetric_encryption ;;
            0) return ;;
            *) echo "Invalid option" ;;
        esac
    done
}

# Function to handle signing and verification menu selection
signing_verification_menu() {
    while true; do
        show_signing_verification_menu
        echo -n "> "
        read -r choice
        case $choice in
            1) sign_document ;;
            2) verify_signature ;;
            3) sign_key ;;
            4) verify_file_integrity ;;
            0) return ;;
            *) echo "Invalid option" ;;
        esac
    done
}

# Function to handle key server operations menu selection
key_server_menu() {
    while true; do
        show_key_server_menu
        echo -n "> "
        read -r choice
        case $choice in
            1) import_key_from_file ;;
            2) import_key_from_keyserver ;;
            3) export_public_key ;;
            4) export_private_key ;;
            5) upload_key_to_keyserver ;;
            6) update_key_on_keyserver ;;
            0) return ;;
            *) echo -e "${YELLOW}Invalid option" ;;
        esac
    done
}

# Function to handle miscellaneous menu selection
miscellaneous_menu() {
    while true; do
        show_miscellaneous_menu
        echo -n "> "
        read -r choice
        case $choice in
            1)
                echo "GPG Version:"
                gpg --version
                ;;
            4)
                echo "GPG Configuration:"
                echo "Home directory: $(gpg --version | grep "Home:" | cut -d: -f2)"
                echo "Configuration file: $(gpg --version | grep "Config file:" | cut -d: -f2)"
                echo "Default key: $(gpg --list-secret-keys --keyid-format LONG | grep sec | cut -d/ -f2 | cut -d' ' -f1 | head -n 1)"
                ;;
            5)
                echo "Supported Algorithms:"
                echo "Public key: $(gpg --version | grep "Pubkey:" | cut -d: -f2)"
                echo "Cipher: $(gpg --version | grep "Cipher:" | cut -d: -f2)"
                echo "Hash: $(gpg --version | grep "Hash:" | cut -d: -f2)"
                echo "Compression: $(gpg --version | grep "Compression:" | cut -d: -f2)"
                ;;
            2)
                while true; do
                    echo ""
                    echo -e "${GREEN}Enter key ID or email to show fingerprint:${NC}"
                    read -r keyid
                    if [ -z "$keyid" ]; then
                        break
                    fi
                    echo ""
                    if gpg --list-keys "$keyid" > /dev/null 2>&1; then
                        gpg --fingerprint "$keyid"
                        break
                    else
                        echo -e "${YELLOW}Please provide a valid key ID or press Enter to continue..."
                    fi
                done
                ;;
            0) return ;;
            *) echo -e "${YELLOW}Invalid option${NC}" ;;
        esac
        echo ""
        echo -e "${GREEN}Press Enter to continue...${NC}"
        read -r
    done
}

# Implement functions for each option
create_key() {
    echo "Creating new key..."
    if gpg --full-generate-key; then
        echo ""
        echo -e "${GREEN}Your key was created successfully. Press Enter to close...${NC}"
    else
        echo ""
        echo -e "${RED}Error creating key. Press Enter to close...${NC}"
    fi
    read -r
}

list_keys() {
    while true; do
        clear
        echo -e "${CYAN}========================================${NC}"
        echo -e "${NC}   Main > Key Management > List Keys${NC}"
        echo -e "${CYAN}========================================${NC}"
        echo -e "${GREEN} 1.${NC} ${NC}Public keys${NC}"
        echo -e "${GREEN} 2.${NC} ${NC}Private keys${NC}"
        echo -e "${GREEN} 3.${NC} ${NC}Back to Key Management${NC}"
        echo -e "${CYAN}========================================${NC}"
        echo -e "${GREEN}Select key type to list:${NC}"
        echo -n "> > > "
        read -r key_type
        case $key_type in
            1|2)
                clear
                echo -e "${CYAN}========================================${NC}"
                echo -e "${NC}           GPG Key Listing              ${NC}"
                echo -e "${CYAN}========================================${NC}"
                echo

                # Run the gpg command and process its output
                if [ "$key_type" -eq 1 ]; then
                    gpg_output=$(gpg --list-keys --keyid-format LONG --with-fingerprint)
                else
                    gpg_output=$(gpg --list-secret-keys --keyid-format LONG --with-fingerprint)
                fi

                # Process the gpg output to add separators and fingerprints
                echo "$gpg_output" | awk '
                    /^pub/ {
                        # Print public key line and the next line
                        pub_line = $0
                        getline
                        print "\033[1;36m" pub_line "\033[0m"
                        print "\033[1;37m" $0 "\033[0m"
                        next
                    }
                    /^sec/ {
                        # Print the secret key line in red and the next line
                        sec_line = $0
                        getline
                        print "\033[1;31m" sec_line "\033[0m"
                        print "\033[1;37m" $0 "\033[0m"
                        next
                    }
                    /^Key fingerprint =/ {
                        # Print the fingerprint line
                        fingerprint = "Huella de clave = " substr($0, 21)
                        next
                    }
                    /^uid/ {
                        # Print the fingerprint if available
                        if (fingerprint != "") {
                            print "\033[1;33m" fingerprint "\033[0m"
                            fingerprint = ""  # Clear fingerprint for next key
                        }
                        sub(/^\s+/, "")  # Remove leading whitespace
                        print "\033[1;32m" $0 "\033[0m"
                    }
                    /^sub/ || /^ssb/ {
                        # Print subkeys (sub/ssb)
                        print "\033[1;33m" $0 "\033[0m"
                    }
                    /^$/ {
                        # Print a separator between keys
                        print "----------------------------------------"
                    }
                '

                echo
                echo -e "${CYAN}========================================${NC}"
                echo -e "${GREEN}Press Enter to continue...${NC}"
                read -r
                ;;
            3)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                echo -e "${GREEN}Press Enter to continue...${NC}"
                read -r
                ;;
        esac
    done
}

import_key_from_file() {
    echo ""
    echo -e "${GREEN}Enter the path to the key file:${NC}"
    read -r key_file

    if [ -f "$key_file" ]; then
        # Import the key
        if gpg --import "$key_file" 2>/tmp/gpg_import_error.log; then
            echo "Key imported successfully."
        else
            echo "Error: Unable to import key. Check the file and try again."
            cat /tmp/gpg_import_error.log
        fi
    else
        echo -e "${YELLOW}Error: File not found!${NC}"
    fi

    echo ""
    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

import_key_from_keyserver() {
    echo ""
    echo -e "${GREEN}Select keyserver:"
    echo -e "${GREEN}1. ${NC}keys.openpgp.org"
    echo -e "${GREEN}2. ${NC}keyserver.ubuntu.com"
    echo -n "> > > "
    read -r keyserver_choice
    case $keyserver_choice in
        1) keyserver="hkps://keys.openpgp.org" ;;
        2) keyserver="hkps://keyserver.ubuntu.com" ;;
        *) echo "Invalid choice. Using keyserver.ubuntu.com by default."
           keyserver="hkps://keyserver.ubuntu.com" ;;
    esac
    echo ""
    echo -e "${GREEN}Enter email, key ID, or fingerprint:${NC}"
    read -r search_identifier
    echo ""
    echo "Searching for key $search_identifier on $keyserver..."

    # Use --dry-run to prevent automatic import during search
    if ! key_info=$(gpg --keyserver "$keyserver" --search-keys --dry-run "$search_identifier" 2>&1); then
        echo ""
        echo -e "${YELLOW}Key not found, try another keyserver."
        echo -e "${GREEN}Press Enter to continue..."
        read -r
        return
    fi
    echo ""
    echo -e "${GREEN}Key found:${NC}"
    echo "$key_info"

    # Extract key ID from the search results
    key_id=$(echo "$key_info" | grep -oP '(?<=key )[A-F0-9]{16}' | head -n1)
    if [ -z "$key_id" ]; then
        echo "Error: Could not extract key ID from search results."
        echo -e "${GREEN}Press Enter to continue..."
        read -r
        return
    fi

    # Check if key already exists
    if gpg --list-keys "$key_id" &>/dev/null; then
        echo ""
        echo -e "${YELLOW}The key is already imported. Do you want to overwrite it? (y/n):${NC}"
        read -r overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            echo ""
            echo -e "${RED}Import cancelled!"
            echo -e "${GREEN}Press Enter to continue..."
            read -r
            return
        fi
    else
        echo ""
        echo -e "${YELLOW}Are you sure you want to proceed with importation? (y/n):${NC}"
        read -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo ""
            echo -e "${RED}Import cancelled!"
            echo -e "${GREEN}Press Enter to continue..."
            read -r
            return
        fi
    fi

    echo ""
    echo "Importing key..."
    if output=$(gpg --keyserver "$keyserver" --recv-keys "$key_id" 2>&1); then
        if echo "$output" | grep -q "not changed"; then
            echo -e "${YELLOW}Key is already up to date."
        else
            echo ""
            echo -e "${GREEN}Key successfully imported or updated!${NC}"
        fi
        echo ""
        echo "Verifying key fingerprint..."
        fingerprint=$(gpg --fingerprint "$key_id" | grep fingerprint | awk '{print $10$11$12$13}')
        #echo "The fingerprint of the imported key is: $fingerprint"
        echo ""
        echo -e "${YELLOW}Please verify this fingerprint with the key owner through a secure channel.${NC}"
        echo "Checking key health..."
        echo ""
        gpg --check-signatures "$key_id"
    else
        echo "Error: Failed to import key. Details:"
        echo "$output"
    fi
    echo ""
    echo -e "${GREEN}Press Enter to continue..."
    read -r
}

export_public_key() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the key ID or fingerprint to export:${NC}"
        read -r keyid

        if [ -z "$keyid" ]; then
            echo -e "${YELLOW}Listing all your public keys due to an empty option:${NC}"
            echo ""
            gpg --list-keys
            echo ""
            echo -e "${GREEN}You must choose one or press Enter to exit...${NC}"
            read -r keyid
            if [ -z "$keyid" ]; then
                return
            fi
        fi

        if gpg --list-keys "$keyid" &> /dev/null; then
            # Export the key to a temporary file
            temp_file=$(mktemp)
            gpg --export --export-options export-minimal --armor "$keyid" > "$temp_file"

            # Display the key content to the user
            cat "$temp_file"

            echo "Write 's' then enter to save to file | ctrl+c to exit | Enter to continue..."
            read -r user_input

            case "$user_input" in
                s|S)
                    # Save the key to the file
                    cp "$temp_file" "${keyid}_public.asc"
                    echo "Public key exported to ${keyid}_public.asc"
                    ;;
                "")
                    # Option to continue without saving
                    echo -e "${CYAN}Key export skipped."
                    ;;
                *)
                    # Handle unexpected input
                    echo -e "${CYAN}Invalid option. Exiting."
                    ;;
            esac

            # Clean up
            rm "$temp_file"

            echo -e "${GREEN}Press Enter to continue or ctrl+c to exit..."
            read -r
            break
        else
            echo -e "${CYAN}Unable to find the key: $keyid"
        fi
    done
}

export_private_key() {
    echo ""
    echo -e "${YELLOW}Warning: Exporting private keys is a security risk. Only do this if absolutely necessary.${NC}"
    echo -e "${GREEN}Are you sure you want to continue? (y/n)${NC}"
    while true; do
        read -r confirm
        case "$confirm" in
            [yY])
                while true; do
                    echo ""
                    echo -e "${GREEN}Enter the key ID, email or fingerprint to export (or press Enter to cancel):${NC}"
                    read -r keyid
                    if [ -z "$keyid" ]; then
                        echo ""
                        echo -e "${YELLOW}The exporting process was cancelled!${NC}"
                        echo -e "${GREEN}Press Enter to continue..."
                        read -r
                        return
                    fi
                    if gpg --list-keys "$keyid" &>/dev/null; then
                        gpg --export-secret-keys --armor "$keyid" > "${keyid}_private.asc"
                        echo "Private key exported to ${keyid}_private.asc"
                        echo "Keep this file secure and never share it!"
                        echo ""
                        echo -e "${GREEN}Exporting process completed! Press Enter to close...${NC}"
                        read -r
                        return
                        break
                    else
                        echo ""
                        echo -e "${YELLOW}The provided key ID, email, or fingerprint is not valid. Please try again.${NC}"
                    fi
                done
                break
                ;;
            [nN])
                echo ""
                echo -e "${YELLOW}The exporting process was cancelled!${NC}"
                echo -e "${GREEN}Press Enter to continue..."
                read -r
                return
                ;;
            *)
                echo -e "${YELLOW}You need to confirm with yes (y) or no (n)${NC}"
                ;;
        esac
    done
}

upload_key_to_keyserver() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the key ID or fingerprint to upload (or press Enter to close):${NC}"
        read -r key_identifier

        if [ -z "$key_identifier" ]; then
            echo "Returning to the menu..."
            return
        fi

        # Verifica el identificador de la clave
        if ! gpg --list-keys --fingerprint "$key_identifier" &> /dev/null; then
            echo ""
            echo -e "${YELLOW}The provided key identifier is not valid. Please try again.${NC}"
            continue
        fi

        echo ""
        echo -e "${GREEN}Select a keyserver:${NC}"
        echo -e "${GREEN}1. ${NC}keys.openpgp.org"
        echo -e "${GREEN}2. ${NC}keyserver.ubuntu.com"
        echo -n "> > > "
        read -r keyserver_choice
        case $keyserver_choice in
            1)
                keyserver="hkps://keys.openpgp.org"
                echo ""
                echo -e "${GREEN}Choose an option:${NC}"
                echo -e "${GREEN}1. ${NC}Send only key information"
                echo -e "${GREEN}2. ${NC}Send identity information"
                echo -n "> > > > "
                read -r opengpg_choice
                case $opengpg_choice in
                    1)
                        echo ""
                        echo "Uploading key $key_identifier to $keyserver..."
                        if gpg --send-keys --keyserver "$keyserver" "$key_identifier"; then
                            echo ""
                            echo -e "${GREEN}Key uploaded successfully. Press Enter to close...${NC}"
                            read -r
                            return
                        else
                            echo ""
                            echo -e "${RED}Error attempting to upload the key. Press Enter to close...${NC}"
                            read -r
                            return
                        fi
                        ;;
                    2)
                        echo ""
                        echo -e "${GREEN}Please provide the email associated to your key:${NC}"
                        read -r email_address
                        echo "Uploading key with identity information to keys.openpgp.org..."
                        if gpg --export "$email_address" | curl -T - https://keys.openpgp.org; then
                            echo ""
                            echo -e "${GREEN}Key with identity uploaded successfully. Press Enter to close...${NC}"
                            read -r
                            return
                        else
                            echo ""
                            echo -e "${RED}Error attempting to upload the key with identity. Press Enter to close...${NC}"
                            read -r
                            return
                        fi
                        ;;
                    *)
                        echo -e "${YELLOW}Invalid choice. Returning to the main menu...${NC}"
                        return
                        ;;
                esac
                ;;
            2)
                keyserver="hkps://keyserver.ubuntu.com"
                echo ""
                echo "Uploading key $key_identifier to $keyserver..."
                if gpg --send-keys --keyserver "$keyserver" "$key_identifier"; then
                    echo ""
                    echo -e "${GREEN}Key uploaded successfully. Press Enter to close...${NC}"
                    read -r
                    return
                else
                    echo ""
                    echo -e "${RED}Error attempting to upload the key. Press Enter to close...${NC}"
                    read -r
                    return
                fi
                ;;
            *)
                echo -e "${YELLOW}Invalid choice. Using keyserver.ubuntu.com by default.${NC}"
                keyserver="hkps://keyserver.ubuntu.com"
                echo ""
                echo "Uploading key $key_identifier to $keyserver..."
                if gpg --send-keys --keyserver "$keyserver" "$key_identifier"; then
                    echo ""
                    echo -e "${GREEN}Key uploaded successfully. Press Enter to close...${NC}"
                    read -r
                    return
                else
                    echo ""
                    echo -e "${RED}Error attempting to upload the key. Press Enter to close...${NC}"
                    read -r
                    return
                fi
                ;;
        esac
    done
}

update_key_on_keyserver() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter key ID or fingerprint to update (press Enter to close):${NC}"
        read -r keyid

        if [ -z "$keyid" ]; then
            echo "Returning to the menu..."
            return
        fi

        # Verify key ID
        if ! gpg --list-keys --fingerprint "$keyid" &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Unable to find that key. Please try again or press Enter to close...${NC}"
            continue
        fi

        echo ""
        echo -e "${GREEN}Select a keyserver:${NC}"
        echo -e "${GREEN}1. ${NC}keys.openpgp.org"
        echo -e "${GREEN}2. ${NC}keyserver.ubuntu.com"
        echo -n "> > > "
        read -r keyserver_choice
        case $keyserver_choice in
            1) keyserver="hkps://keys.openpgp.org" ;;
            2) keyserver="hkps://keyserver.ubuntu.com" ;;
            *) echo -e "${YELLOW}Invalid choice. Using keyserver.ubuntu.com by default...${NC}"
               keyserver="hkps://keyserver.ubuntu.com" ;;
        esac

        echo ""
        echo "Updating key $keyid on $keyserver..."
        if gpg --keyserver "$keyserver" --send-keys "$keyid"; then
            echo ""
            echo -e "${GREEN}Key successfully updated at $keyserver. Press Enter to close...${NC}"
            read -r
            return
        else
            echo ""
            echo -e "${RED}Error updating key at $keyserver. Press Enter to close...${NC}"
            read -r
            return
        fi
    done
}


backup_restore() {
    while true; do
        clear
        echo -e "${CYAN}========================================${NC}"
        echo -e "${NC}        Main > Backup and Restore${NC}"
        echo -e "${CYAN}========================================${NC}"
        echo -e "${GREEN}Please select an option:${NC}"
        echo -e "${GREEN} 1.${NC} ${NC}Backup keys${NC}"
        echo -e "${GREEN} 2.${NC} ${NC}Restore keys${NC}"
        echo -e "${GREEN} 0.${NC} ${NC}Back to main menu${NC}"
        echo -e "${CYAN}========================================${NC}"
        echo -e "${GREEN}Please select an option:${NC}"
        echo -n "> "
        read -r choice
        case $choice in
            1)
                echo ""
                echo -e "${GREEN}Enter backup file name (or press Enter to cancel):${NC}"
                read -r backup_file

                if [ -z "$backup_file" ]; then
                    echo -e "${YELLOW}Backup cancelled!${NC}"
                    echo -e "${GREEN}Press Enter to continue...${NC}"
                    read -r
                    continue
                fi

                # Verificar si hay claves públicas para exportar
                if ! gpg --list-keys > /dev/null 2>&1; then
                    echo -e "${YELLOW}No public keys found. Backup cannot proceed.${NC}"
                    echo -e "${GREEN}Press Enter to continue...${NC}"
                    read -r
                    continue
                fi

                # Realizar el backup de claves públicas
                gpg --export --export-options backup --output "$backup_file" --yes
                if [ $? -ne 0 ]; then
                    echo -e "${RED}Error exporting public keys.${NC}"
                    echo -e "${GREEN}Press Enter to continue...${NC}"
                    read -r
                    continue
                fi

                # Realizar el backup de claves secretas
                gpg --export-secret-keys --export-options backup --output "${backup_file}_secret" --yes
                if [ $? -ne 0 ]; then
                    echo -e "${RED}Error exporting secret keys.${NC}"
                    echo -e "${GREEN}Press Enter to continue...${NC}"
                    read -r
                    continue
                fi

                echo ""
                echo "Backup completed. Public keys in $backup_file, secret keys in ${backup_file}_secret"
                echo -e "${GREEN}Press Enter to continue...${NC}"
                read -r
                ;;
            2)
                echo ""
                echo -e "${GREEN}Enter backup file name to restore:${NC}"
                read -r backup_file

                # Verificar si el archivo de respaldo existe
                if [ ! -f "$backup_file" ]; then
                    echo "Backup file $backup_file does not exist."
                    echo -e "${GREEN}Press Enter to continue...${NC}"
                    read -r
                    continue
                fi

                # Restaurar las claves públicas
                gpg --import "$backup_file"
                if [ $? -ne 0 ]; then
                    echo -e "${RED}Error importing public keys.${NC}"
                    echo -e "${GREEN}Press Enter to continue...${NC}"
                    read -r
                    continue
                fi

                # Restaurar las claves secretas si el usuario lo confirma
                echo ""
                echo -e "${YELLOW}Do you want to restore secret keys as well? (y/n)${NC}"
                read -r confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    if [ ! -f "${backup_file}_secret" ]; then
                        echo -e "${RED}Secret key backup file ${backup_file}_secret does not exist.${NC}"
                        echo -e "${CYAN}Press Enter to continue...${NC}"
                        read -r
                        continue
                    fi
                    gpg --import "${backup_file}_secret"
                    if [ $? -ne 0 ]; then
                        echo -e "${RED}Error importing secret keys.${NC}"
                        echo -e "${GREEN}Press Enter to continue...${NC}"
                        read -r
                        continue
                    fi
                fi

                echo -e "${GREEN}Restore completed!${NC}"
                echo -e "${GREEN}Press Enter to continue...${NC}"
                read -r
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                echo -e "${GREEN}Press Enter to continue...${NC}"
                read -r
                ;;
        esac
    done
}

sign_document() {
    echo ""
    echo -e "${GREEN}Enter the path to the document to sign:${NC}"
    read -r document
    if [ -f "$document" ]; then
        echo ""
        echo -e "${GREEN}What kind of sign do you want to implement?$NC"
        echo -e "${GREEN} 1.${NC} Clearsign"
        echo -e "${GREEN} 2.${NC} Detach-sign"
        echo -n "> > > "
        read -r choice
        case $choice in
            1)
                gpg --clearsign "$document"
                echo ""
                echo -e "${GREEN}Document signed successfully with clearsign.${NC}"
                ;;
            2)
                gpg --detach-sign "$document"
                echo ""
                echo -e "${GREEN}Document signed successfully with detach-sign.${NC}"
                ;;
            *)
                echo -e "${YELLOW}Invalid option. Please choose 1 or 2.${NC}"
                ;;
        esac
    else
        echo ""
        echo -e "${YELLOW}Error: File not found!${NC}"
    fi
    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

encrypt_document() {
    echo ""
    echo -e "${GREEN}Enter the path to the document to encrypt:${NC}"
    read -r document
    echo ""

    if [ ! -f "$document" ]; then
        echo -e "${YELLOW}Error: File not found${NC}"
        echo -e "${GREEN}Press Enter to continue...${NC}"
        read -r
        return
    fi

    while true; do
        echo -e "${GREEN}Enter the recipient's email or public key ID (or press Enter to return to menu):${NC}"
        read -r recipient

        if [ -z "$recipient" ]; then
            echo "Returning to menu..."
            return
        fi

        if ! gpg --list-keys "$recipient" &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Recipient not found, please try again!${NC}"
            echo ""
        else
            break
        fi
    done

    output_file="${document}.gpg"
    if gpg --output "$output_file" --encrypt --recipient "$recipient" "$document"; then
        echo ""
        echo "File successfully encrypted and saved as: $output_file"
    else
        echo -e "${RED}Error: Encryption failed${NC}"
    fi

    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

decrypt_document() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the path to the document to decrypt (or press Enter to return to menu):${NC}"
        read -r document

        if [ -z "$document" ]; then
            echo "Returning to menu..."
            return
        fi

        if [ ! -f "$document" ]; then
            echo ""
            echo -e "${YELLOW}Invalid document!${NC}"
            echo -e "Provide a valid document or press Enter to return to menu..."
        else
            break
        fi
    done

    output_file="${document%.gpg}.decrypted"
    if gpg --decrypt "$document" > "$output_file" 2>/dev/null; then
        echo ""
        echo "Your decrypted file was saved as: $output_file"
        echo ""
        echo -e "${GREEN}File successfully decrypted!${NC}"
    else
        echo -e "${RED}Error: Decryption failed!${NC}"
        rm -f "$output_file"  # Remove the output file if decryption failed
    fi

    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

edit_key() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter key ID, email or fingerprint to edit:${NC}"
        read -r keyid
        echo ""

        if [[ -z "$keyid" ]]; then
            echo -e "${RED}Unable to process empty options!${NC}"
            echo -e "${GREEN}Try again or Press Enter to back to menu...${NC}"
            read -r keyid
            echo ""

            if [[ -z "$keyid" ]]; then
                return
            fi
        fi

        if ! gpg --list-keys "$keyid" &>/dev/null; then
            echo -e "${YELLOW}Invalid key ID. Please try again...${NC}"
            continue
        fi

        # Si llegamos aquí, el keyid es válido
        if gpg --edit-key "$keyid"; then
            echo -e "${GREEN}Key editing completed. Press Enter to continue...${NC}"
            read
            return
        else
            echo -e "${RED}An error occurred while editing the key.${NC}"
            echo "Press Enter to try again or enter 'q' to quit:"
            read -r response
            if [[ "$response" == "q" ]]; then
                return
            fi
        fi
    done
}

symmetric_encryption() {
    echo ""
    echo -e "${GREEN}Enter the path to the document to encrypt:${NC}"
    read -r document
    echo ""

    if [ ! -f "$document" ]; then
        echo -e "${YELLOW}Error: File not found${NC}"
        echo -e "${GREEN}Press Enter to continue...${NC}"
        read -r
        return
    fi

    output_file="${document}.gpg"

    if gpg --symmetric --output "$output_file" "$document"; then
        echo "Document successfully encrypted as: $output_file"
    else
        echo -e "${RED}Error: Encryption failed${NC}"
    fi

    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

verify_signature() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the path to the signed document:${NC}"
        read -r document

        if [ -z "$document" ]; then
            echo -e "${YELLOW}No document path provided!${NC}"
            echo -e "${GREEN}Press Enter to try again or type 'exit' to return to the Signing and Verification menu.${NC}"
            read -r user_input
            if [ "$user_input" == "exit" ]; then
                return
            fi
            continue
        fi

        if [ -f "$document" ]; then
            # Try to verify the signature
            gpg --verify "$document" 2>&1 | tee /tmp/verify_output.log
            result=$?

            # Check the result of the gpg command
            if [ $result -ne 0 ]; then
                echo ""
                echo -e "${YELLOW}Verification failed. Here is the error message:${NC}"
                cat /tmp/verify_output.log
                echo "Press Enter to try again or type 'exit' to return to the Signing and Verification menu."
                read -r user_input
                if [ "$user_input" == "exit" ]; then
                    return
                fi
            else
                echo ""
                echo -e "${GREEN}Signature verification successful!${NC}"
                echo -e "${GREEN}Press Enter to continue...${NC}"
                read -r
                return
            fi
        else
            echo ""
            echo -e "${YELLOW}Error: File not found!${NC}"
            echo -e "${GREEN}Press Enter to try again or type 'exit' to return to the Signing and Verification menu.${NC}"
            read -r user_input
            if [ "$user_input" == "exit" ]; then
                return
            fi
        fi
    done
}

sign_key() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter key ID, email or fingerprint to sign:${NC}"
        read -r keyid
        if [ -z "$keyid" ]; then
            break
        fi
        if gpg --list-keys "$keyid" > /dev/null 2>&1; then
            gpg --sign-key "$keyid"
            echo -e "${GREEN}Key signed successfully!${NC}"
            break
        else
            echo ""
            echo -e "${YELLOW}Unable to find that key ID!${NC}"
            echo -e "${GREEN}Introduce a valid key ID or press Enter to continue...${NC}"
        fi
    done
    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

verify_file_integrity() {
    echo ""
    echo -e "${GREEN}Enter the path to the file to verify:${NC}"
    read -r file

    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found."
        echo -e "${GREEN}Press Enter to continue...${NC}"
        read -r
        return
    fi

    # Determine the type of file
    file_type=$(file -b "$file")

    if echo "$file_type" | grep -q "PGP signature"; then
        echo -e "${GREEN}Detached signature detected. Enter the path to the original file:${NC}"
        read -r original_file
        if [ ! -f "$original_file" ]; then
            echo "Error: Original file '$original_file' not found."
            echo -e "${GREEN}Press Enter to continue...${NC}"
            read -r
            return
        fi
        echo "Verifying file integrity with detached signature..."
        if gpg --verify "$file" "$original_file" 2>&1; then
            echo -e "${GREEN}Verification successful.${NC}"
        else
            echo -e "${RED}Verification failed or encountered an error.${NC}"
        fi
    elif echo "$file_type" | grep -q "PGP.*encrypted"; then
        echo "PGP encrypted file detected."
        echo -e "${GREEN}Would you like to attempt to decrypt it? (y/n):${NC}"
        read -r decrypt_choice
        if [[ "$decrypt_choice" =~ ^[Yy]$ ]]; then
            if gpg --decrypt "$file" > "${file}.decrypted" 2>&1; then
                echo "File decrypted successfully. The decrypted file is saved as ${file}.decrypted"
                echo -e "${GREEN}Would you like to verify the signature of the decrypted file? (y/n):${NC}"
                read -r verify_choice
                if [[ "$verify_choice" =~ ^[Yy]$ ]]; then
                    if gpg --verify "${file}.decrypted" 2>&1; then
                        echo -e "${GREEN}Signature verification successful.${NC}"
                    else
                        echo -e "${RED}Signature verification failed or encountered an error.${NC}"
                    fi
                fi
            else
                echo -e "${YELLOW}Decryption failed. This could be due to not having the necessary private key or other issues.${NC}"
            fi
        else
            echo -e "${YELLOW}Decryption cancelled. Cannot verify integrity of an encrypted file without decrypting.${NC}"
        fi
    elif echo "$file_type" | grep -q "PGP message"; then
        echo "PGP message detected. Attempting to verify..."
        if gpg --verify "$file" 2>&1; then
            echo -e "${GREEN}Verification successful!${NC}"
        else
            echo "Verification failed or encountered an error."
        fi
    else
        echo "This file doesn't appear to be a standard PGP file."
        echo "File type: $file_type"
        echo "Attempting general GPG verification..."
        if gpg --verify "$file" 2>&1; then
            echo ""
            echo -e "${GREEN}File verified successfully!${NC}"
        else
            echo ""
            echo -e "${YELLOW}Unable to verify this file. It might be encrypted or in an unsupported format.${NC}"
        fi
    fi

    echo -e "${GREEN}Press Enter to continue...${NC}"
    read -r
}

delete_key() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the key ID to delete (Leave blank to go back):${NC}"
        read -r keyid

        # Check if the user pressed Enter without entering a key ID
        if [ -z "$keyid" ]; then
            echo "Returning to Key Management menu..."
            return
        fi

        # Check if the key ID is valid by attempting to list the key
        if ! gpg --list-keys "$keyid" >/dev/null 2>&1; then
            echo ""
            echo "Unable to find the key: $keyid"
            echo -e "${YELLOW}Please provide a valid key ID or press Enter to close...${NC}"
            continue
        fi

        echo ""
        echo -e "${YELLOW}Are you sure to delete this key? (y/n)${NC}"
        read -r response
        echo ""

        if [[ "$response" =~ ^[Yy]$ ]]; then
            # Delete both private and public keys
            gpg --delete-secret-and-public-key "$keyid"
            echo ""
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Key deleted successfully.${NC}"
            else
                echo -e "${RED}Error: Failed to delete the key.${NC}"
            fi
        else
            # Delete only the public key
            gpg --delete-key "$keyid"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Key deleted successfully.${NC}"
            else
                echo -e "${RED}Error: Failed to delete the key.${NC}"
            fi
        fi
        echo -e "${GREEN}Press Enter to continue..."
        read -r
        return
    done
}

revoke_key() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the key ID to revoke:${NC}"
        read -r keyid
        echo ""

        if [[ -z "$keyid" ]]; then
            echo -e "${RED}Unable to process empty options!${NC}"
            echo -e "${GREEN}Try again or Press Enter to back to menu...${NC}"
            read -r keyid
            echo ""

            if [[ -z "$keyid" ]]; then
                return
            fi
        fi

        if ! gpg --list-keys "$keyid" &>/dev/null; then
            echo -e "${YELLOW}The provided key is not a valid one. Please try again...${NC}"
            continue
        fi

        echo -e "${YELLOW}Are you sure you want to revoke this key? This action cannot be undone. (y/N)${NC}"
        read -r confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo -e "${RED}Revocation cancelled!${NC}"
            return
        fi

        if gpg --key-revoke "$keyid"; then
            echo ""
            echo "The key $keyid has been successfully revoked."
            echo "Please remember to update this revoked status to your keyservers."
            echo -e "${GREEN}Press Enter to continue...${NC}"
            read
            return
        else
            echo -e "${RED}An error occurred while revoking the key!${NC}"
            echo "Press Enter to try again or enter 'q' to quit:"
            read -r response
            if [[ "$response" == "q" ]]; then
                return
            fi
        fi
    done
}

generate_revocation_certificate() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter the key ID to generate a revocation certificate for:${NC}"
        read -r keyid
        if [[ -z "$keyid" ]]; then
            echo -e "${RED}Unable to process empty options!${NC}"
            echo -e "${GREEN}Try again or Press Enter to back to menu...${NC}"
            read -r keyid
            echo ""

            if [[ -z "$keyid" ]]; then
                return
            fi
        fi
        if ! gpg --list-keys "$keyid" &>/dev/null; then
            echo -e "${YELLOW}The provided key is not a valid one. Please try again...${NC}"
            continue
        fi
        if gpg --output "${keyid}_revocation.asc" --gen-revoke "$keyid"; then
            echo ""
            echo "Revocation certificate generated and saved as: ${keyid}_revocation.asc"
            echo -e "${GREEN}Press Enter to continue...${NC}"
            read
            return
        else
            echo -e "${RED}An error occurred while generating the revocation certificate!${NC}"
            echo "Press Enter to try again or enter 'q' to quit:"
            read -r response
            if [[ "$response" == "q" ]]; then
                return
            fi
        fi
    done
}

manage_subkeys() {
    while true; do
        echo ""
        echo -e "${GREEN}Enter key ID, email or fingerprint to manage subkeys (or press Enter to return):${NC}"
        read -r keyid

        if [ -z "$keyid" ]; then
            echo "Returning to Key Management menu..."
            return
        fi

        while ! gpg --list-keys "$keyid" > /dev/null 2>&1; do
            echo ""
            echo -e "${YELLOW}Invalid key ID or fingerprint!${NC}"
            echo -e "${GREEN}Try again or press Enter to return to the menu...${NC}"
            read -r keyid

            if [ -z "$keyid" ]; then
                echo "Returning to Key Management menu..."
                return
            fi
        done

        # Si llegamos aquí, el keyid es válido
        echo "Managing subkeys for key $keyid"
        echo "Use 'addkey', 'key X' (where X is the subkey number), and 'expire' commands in the GPG prompt to manage subkeys."
        gpg --edit-key "$keyid"
        echo "Subkey management completed. Press Enter to continue..."
        read -r
        return
    done
}

change_passphrase() {
    echo "Enter the key ID to change passphrase:"
    read -r keyid
    gpg --passwd "$keyid"
}

modify_key_expiration() {
    echo ""
    echo -e "${GREEN}Enter key ID, email or fingerprint to modify expiration:${NC}"
    read -r keyid

    # Key ID validation
    if [ -z "$keyid" ]; then
        echo -e "${YELLOW}Key ID cannot be empty. Press Enter to continue...${NC}"
        read -r
        return
    fi

    # Check if the key ID exists in the keyring
    if ! gpg --list-keys "$keyid" >/dev/null 2>&1; then
        echo ""
        echo -e "${YELLOW}Invalid key ID. Press Enter to continue...${NC}"
        read -r
        return
    fi

    echo -e "${GREEN}Enter new expiration period (e.g., 1y for one year, 6m for six months).${NC}"
    echo -e "${GREEN}Leave empty for no expiration:${NC}"
    read -r expiration

    # Create temp file for GPG commands
    temp_file=$(mktemp)

    if [ -z "$expiration" ]; then
        # If empty no expiration
        {
            echo "expire"
            echo ""
            echo "key 1"
            echo "expire"
            echo ""
            echo "save"
        } > "$temp_file"
    else
        # If non empty uses the input duration
        {
            echo "expire"
            echo "$expiration"
            echo "key 1"
            echo "expire"
            echo "$expiration"
            echo "save"
        } > "$temp_file"
    fi

    # Ask for the passphrase
    echo -e "${GREEN}Enter the passphrase for the key:${NC}"
    read -s passphrase

    # Execute GPG with temp file's commands
    echo "$passphrase" | gpg --pinentry-mode loopback --batch --passphrase-fd 0 --command-file "$temp_file" --edit-key "$keyid"

    # Capture the GPG commands output
    status=$?

    # Remove the temp file
    rm -f "$temp_file"

    if [ $status -eq 0 ]; then
        echo -e "${GREEN}Key expiration modified successfully. Press Enter to continue...${NC}"
    else
        echo -e "${YELLOW}An error occurred while modifying the key expiration. Please check the errors above. Press Enter to continue...${NC}"
    fi

    read -r
}

clean_keyring() {
    expired_keys=$(gpg --list-keys | grep -E "^pub\s+\[expired: " | awk '{print $2}' | cut -d'/' -f2)

    if [ -z "$expired_keys" ]; then
        echo ""
        echo -e "${GREEN}The keyring is clean, nothing to do. Press Enter to continue...${NC}"
    else
        if gpg --delete-key --yes $expired_keys; then
            echo ""
            echo -e "${GREEN}Keyring clean successfully. Press Enter to continue...${NC}"
        else
            echo ""
            echo -e "${YELLOW}An error occurred while cleaning the keyring. Please check the errors above. Press Enter to continue...${NC}"
        fi
    fi

    read -r
}

# Main function
main() {
    check_gpg_installed
    while true; do
        show_main_menu
        read -r choice
        handle_main_selection "$choice"
    done
}

# Parse command line options
TEMP=$(getopt -o hv --long help,version -n 'gpgmng' -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

while true ; do
    case "$1" in
        -h|--help) usage ; exit 0 ;;
        -v|--version) version ; exit 0 ;;
        --) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

# Run the main function
main