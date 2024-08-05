#!/bin/bash

set -e

# Function to display usage information
usage() {
    echo "Usage: $0 [OPTION]"
    echo "Manage GPG functionalities"
    echo ""
    echo "Options:"
    echo "  -h, --help     Display this help message"
    echo "  -v, --version  Display version information"
}

# Function to display version information
version() {
    echo "gpgmngr (GPG Manager) 1.0.0"
}

# Function to check if GPG is installed
check_gpg_installed() {
    if ! command -v gpg &> /dev/null; then
        echo "GPG is not installed. Do you want to install it? (y/n)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            sudo apt-get update
            sudo apt-get install gnupg
        else
            echo "GPG is necessary for this program. Exiting."
            exit 1
        fi
    else
        version=$(gpg --version | head -n 1)
        echo "GPG is installed. Version: $version"
    fi
}

# Function to display the main menu
show_main_menu() {
    clear
    echo "GPG Manager. Please select an option:"
    echo " 1. Key Management"
    echo " 2. Encryption and Decryption"
    echo " 3. Signing and Verification"
    echo " 4. Key Trade Operations"
    echo " 5. Backup and Restore"
    echo " 6. Miscellaneous"
    echo " 7. Exit"
    echo -n "> "
}

# Function to display the key management submenu
show_key_management_menu() {
    clear
    echo "Main > Key Management:"
    echo " 1. Create new key"
    echo " 2. List keys"
    echo " 3. Edit key"
    echo " 4. Delete key"
    echo " 5. Revoke key"
    echo " 6. Generate revocation certificate"
    echo " 7. Manage subkeys"
    echo " 8. Change passphrase"
    echo " 9. Modify key expiration"
    echo " 10. Clean keyring"
    echo " 11. Back to main menu"
}

# Function to display the encryption and decryption submenu
show_encryption_decryption_menu() {
    clear
    echo "Main > Encryption and Decryption:"
    echo " 1. Encrypt document"
    echo " 2. Decrypt document"
    echo " 3. Symmetric encryption"
    echo " 4. Back to main menu"
}

# Function to display the signing and verification submenu
show_signing_verification_menu() {
    clear
    echo "Main > Signing and Verification:"
    echo " 1. Sign document"
    echo " 2. Verify signature"
    echo " 3. Sign key"
    echo " 4. Verify file integrity"
    echo " 5. Back to main menu"
}

# Function to display the key server operations submenu
show_key_server_menu() {
    clear
    echo "Main > Key Trade Operations:"
    echo " 1. Import key from file"
    echo " 2. Import key from keyserver"
    echo " 3. Export public key"
    echo " 4. Export private key"
    echo " 5. Upload key to keyserver"
    echo " 6. Update key on keyserver"
    echo " 7. Back to main menu"
}

# Function to display the miscellaneous menu
show_miscellaneous_menu() {
    clear
    echo "Main > Miscellaneous Operations:"
    echo " 1. Show GPG config info"
    echo " 2. Show key fingerprint"
    echo " 3. Back to main menu"
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
        7) exit 0 ;;
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
            11) return ;;
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
            4) return ;;
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
            5) return ;;
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
            7) return ;;
            *) echo "Invalid option" ;;
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
                    echo "Enter the key ID to show fingerprint:"
                    read -r keyid
                    if [ -z "$keyid" ]; then
                        break
                    fi
                    if gpg --list-keys "$keyid" > /dev/null 2>&1; then
                        gpg --fingerprint "$keyid"
                        break
                    else
                        echo "Please provide a valid key ID or press Enter to continue..."
                    fi
                done
                ;;
            3) return ;;
            *) echo "Invalid option" ;;
        esac
        echo "Press Enter to continue..."
        read -r
    done
}

# Implement functions for each option
create_key() {
    echo "Creating new key..."
    gpg --full-generate-key
}

list_keys() {
    while true; do
        clear
        echo "Main > Key Management > List Keys"
        echo "Select key type to list:"
        echo " 1. Public keys"
        echo " 2. Private keys"
        echo " 3. Back to Key Management"
        read -r key_type
        case $key_type in
            1)
                gpg --list-keys
                ;;
            2)
                gpg --list-secret-keys
                ;;
            3)
                return
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
        echo "Press Enter to continue..."
        read -r
    done
}

import_key_from_file() {
    echo "Enter the path to the key file:"
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
        echo "Error: File not found"
    fi

    echo "Press Enter to continue or ctrl+c to exit..."
    read -r
}

import_key_from_keyserver() {
    echo "Select keyserver:"
    echo "1. keys.openpgp.org"
    echo "2. keyserver.ubuntu.com"
    read -r keyserver_choice
    case $keyserver_choice in
        1) keyserver="hkps://keys.openpgp.org" ;;
        2) keyserver="hkps://keyserver.ubuntu.com" ;;
        *) echo "Invalid choice. Using keys.openpgp.org by default."
           keyserver="hkps://keys.openpgp.org" ;;
    esac
    echo "Enter email, key ID, or fingerprint:"
    read -r search_identifier
    echo "Searching for key $search_identifier on $keyserver..."

    # Use --dry-run to prevent automatic import during search
    if ! key_info=$(gpg --keyserver "$keyserver" --search-keys --dry-run "$search_identifier" 2>&1); then
        echo "Key not found, try another keyserver."
        echo "Press Enter to continue..."
        read -r
        return
    fi
    echo "Key found:"
    echo "$key_info"

    # Extract key ID from the search results
    key_id=$(echo "$key_info" | grep -oP '(?<=key )[A-F0-9]{16}' | head -n1)
    if [ -z "$key_id" ]; then
        echo "Error: Could not extract key ID from search results."
        echo "Press Enter to continue..."
        read -r
        return
    fi

    # Check if key already exists
    if gpg --list-keys "$key_id" &>/dev/null; then
        echo "The key is already imported. Do you want to overwrite it? (y/n):"
        read -r overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            echo "Import cancelled."
            echo "Press Enter to continue..."
            read -r
            return
        fi
    else
        echo "Are you sure you want to proceed with importation? (y/n):"
        read -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Import cancelled."
            echo "Press Enter to continue..."
            read -r
            return
        fi
    fi

    echo "Importing key..."
    if output=$(gpg --keyserver "$keyserver" --recv-keys "$key_id" 2>&1); then
        if echo "$output" | grep -q "not changed"; then
            echo "Key is already up to date."
        else
            echo "Key successfully imported or updated."
        fi
        echo "Verifying key fingerprint..."
        fingerprint=$(gpg --fingerprint "$key_id" | grep fingerprint | awk '{print $10$11$12$13}')
        echo "The fingerprint of the imported key is: $fingerprint"
        echo "Please verify this fingerprint with the key owner through a secure channel."
        echo "Checking key health..."
        gpg --check-signatures "$key_id"
    else
        echo "Error: Failed to import key. Details:"
        echo "$output"
    fi
    echo "Press Enter to continue..."
    read -r
}

export_public_key() {
    while true; do
        echo "Enter the key ID or fingerprint to export:"
        read -r keyid

        if [ -z "$keyid" ]; then
            echo "Listing all your public keys due to an empty option:"
            gpg --list-keys
            echo "You must choose one or press Enter to exit..."
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
                    echo "Key export skipped."
                    ;;
                *)
                    # Handle unexpected input
                    echo "Invalid option. Exiting."
                    ;;
            esac

            # Clean up
            rm "$temp_file"

            echo "Press Enter to continue or ctrl+c to exit..."
            read -r
            break
        else
            echo "Unable to find the key: $keyid"
        fi
    done
}



export_private_key() {
    echo "Warning: Exporting private keys is a security risk. Only do this if absolutely necessary."
    echo "Are you sure you want to continue? (y/n)"
    read -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo "Enter the key ID to export:"
        read -r keyid
        gpg --export-secret-keys --armor "$keyid" > "${keyid}_private.asc"
        echo "Private key exported to ${keyid}_private.asc"
        echo "Keep this file secure and never share it!"
    fi
}

upload_key_to_keyserver() {
    echo "Enter the key ID to upload:"
    read -r keyid
    echo "Enter the keyserver URL (e.g., hkps://keys.openpgp.org):"
    read -r keyserver
    gpg --keyserver "$keyserver" --send-keys "$keyid"
}

update_key_on_keyserver() {
    echo "Enter the key ID to update:"
    read -r keyid
    echo "Enter the keyserver URL (e.g., hkps://keys.openpgp.org):"
    read -r keyserver
    gpg --keyserver "$keyserver" --send-keys "$keyid"
}

backup_restore() {
    clear
    while true; do
        clear
        echo "Main > Backup and Restore:"
        echo "1. Backup keys"
        echo "2. Restore keys"
        echo "3. Back to main menu"
        read -r choice
        case $choice in
            1)
                echo "Enter backup file name:"
                read -r backup_file

                # Verificar si hay claves públicas para exportar
                if ! gpg --list-keys > /dev/null 2>&1; then
                    echo "No public keys found. Backup cannot proceed."
                    continue
                fi

                # Realizar el backup de claves públicas
                gpg --export --export-options backup --output "$backup_file" --yes
                if [ $? -ne 0 ]; then
                    echo "Error exporting public keys."
                    continue
                fi

                # Realizar el backup de claves secretas
                gpg --export-secret-keys --export-options backup --output "${backup_file}_secret" --yes
                if [ $? -ne 0 ]; then
                    echo "Error exporting secret keys."
                    continue
                fi

                echo "Backup completed. Public keys in $backup_file, secret keys in ${backup_file}_secret"
                echo "Press ctrl+c to exit or Enter to continue..."
                read -r
                ;;
            2)
                echo "Enter backup file name to restore:"
                read -r backup_file

                # Verificar si el archivo de respaldo existe
                if [ ! -f "$backup_file" ]; then
                    echo "Backup file $backup_file does not exist."
                    continue
                fi

                # Restaurar las claves públicas
                gpg --import "$backup_file"
                if [ $? -ne 0 ]; then
                    echo "Error importing public keys."
                    continue
                fi

                # Restaurar las claves secretas si el usuario lo confirma
                echo "Do you want to restore secret keys as well? (y/n)"
                read -r confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    if [ ! -f "${backup_file}_secret" ]; then
                        echo "Secret key backup file ${backup_file}_secret does not exist."
                        continue
                    fi
                    gpg --import "${backup_file}_secret"
                    if [ $? -ne 0 ]; then
                        echo "Error importing secret keys."
                        continue
                    fi
                fi

                echo "Restore completed."
                echo "Press ctrl+c to exit or Enter to continue..."
                read -r
                ;;
            3)
                return
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
    done
}



sign_document() {
    echo "Enter the path to the document to sign:"
    read -r document
    if [ -f "$document" ]; then
        echo "What kind of sign do you want to implement?"
        echo "1. Clearsign"
        echo "2. Detach-sign"
        read -r choice
        case $choice in
            1)
                gpg --clearsign "$document"
                echo "Document signed successfully with clearsign."
                ;;
            2)
                gpg --detach-sign "$document"
                echo "Document signed successfully with detach-sign."
                ;;
            *)
                echo "Invalid option. Please choose 1 or 2."
                ;;
        esac
    else
        echo "Error: File not found."
    fi
    echo "Press Enter to continue..."
    read -r
}




encrypt_document() {
    echo "Enter the path to the document to encrypt:"
    read -r document
    echo "Enter the recipient's email or public key ID:"
    read -r recipient

    if [ ! -f "$document" ]; then
        echo "Error: File not found"
        return
    fi

    if ! gpg --list-keys "$recipient" &> /dev/null; then
        echo "Error: Public key for recipient not found or cannot be used"
        return
    fi

    output_file="${document}.gpg"

    if gpg --output "$output_file" --encrypt --recipient "$recipient" "$document"; then
        echo "File successfully encrypted and saved as $output_file"
        echo "Press Enter to continue..."
        read -r
    else
        echo "Error: Encryption failed"
        echo "Press Enter to continue..."
        read -r
    fi
}



decrypt_document() {
    echo "Enter the path to the document to decrypt:"
    read -r document

    if [ ! -f "$document" ]; then
        echo "Error: File not found"
        return
    fi

    output_file="${document%.gpg}.decrypted"

    if gpg --decrypt "$document" > "$output_file"; then
        echo "Your decrypted file was saved at $output_file"
        echo "File successfully decrypted, press Enter to continue..."
        read -r
    else
        echo "Error: Decryption failed"
    fi
}

edit_key() {
    echo "Enter the key ID to edit:"
    read -r keyid
    gpg --edit-key "$keyid"
}

symmetric_encryption() {
    echo "Enter the path to the document to encrypt:"
    read -r document
    if [ -f "$document" ]; then
        gpg --symmetric "$document"
    else
        echo "Error: File not found"
    fi
}

verify_signature() {
    while true; do
        echo "Enter the path to the signed document:"
        read -r document

        if [ -z "$document" ]; then
            echo "No document path provided."
            echo "Press Enter to try again or type 'exit' to return to the Signing and Verification menu."
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
                echo "Verification failed. Here is the error message:"
                cat /tmp/verify_output.log
                echo "Press Enter to try again or type 'exit' to return to the Signing and Verification menu."
                read -r user_input
                if [ "$user_input" == "exit" ]; then
                    return
                fi
            else
                echo "Signature verification successful."
                echo "Press Enter to continue..."
                read -r
                return
            fi
        else
            echo "Error: File not found"
            echo "Press Enter to try again or type 'exit' to return to the Signing and Verification menu."
            read -r user_input
            if [ "$user_input" == "exit" ]; then
                return
            fi
        fi
    done
}



sign_key() {
    while true; do
        echo "Enter the key ID to sign:"
        read -r keyid
        if [ -z "$keyid" ]; then
            break
        fi
        if gpg --list-keys "$keyid" > /dev/null 2>&1; then
            gpg --sign-key "$keyid"
            echo "Key signed successfully."
            break
        else
            echo "Unable to find that key ID!"
            echo "Introduce a valid key ID or press Enter to continue..."
        fi
    done
    echo "Press Enter to continue..."
    read -r
}


verify_file_integrity() {
    echo "Enter the path to the file to verify:"
    read -r file

    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found."
        echo "Press Enter to continue..."
        read -r
        return
    fi

    # Determine the type of file
    file_type=$(file -b "$file")

    if echo "$file_type" | grep -q "PGP signature"; then
        echo "Detached signature detected. Enter the path to the original file:"
        read -r original_file
        if [ ! -f "$original_file" ]; then
            echo "Error: Original file '$original_file' not found."
            echo "Press Enter to continue..."
            read -r
            return
        fi
        echo "Verifying file integrity with detached signature..."
        if gpg --verify "$file" "$original_file" 2>&1; then
            echo "Verification successful."
        else
            echo "Verification failed or encountered an error."
        fi
    elif echo "$file_type" | grep -q "PGP.*encrypted"; then
        echo "PGP encrypted file detected."
        echo "Would you like to attempt to decrypt it? (y/n)"
        read -r decrypt_choice
        if [[ "$decrypt_choice" =~ ^[Yy]$ ]]; then
            if gpg --decrypt "$file" > "${file}.decrypted" 2>&1; then
                echo "File decrypted successfully. The decrypted file is saved as ${file}.decrypted"
                echo "Would you like to verify the signature of the decrypted file? (y/n)"
                read -r verify_choice
                if [[ "$verify_choice" =~ ^[Yy]$ ]]; then
                    if gpg --verify "${file}.decrypted" 2>&1; then
                        echo "Signature verification successful."
                    else
                        echo "Signature verification failed or encountered an error."
                    fi
                fi
            else
                echo "Decryption failed. This could be due to not having the necessary private key or other issues."
            fi
        else
            echo "Decryption cancelled. Cannot verify integrity of an encrypted file without decrypting."
        fi
    elif echo "$file_type" | grep -q "PGP message"; then
        echo "PGP message detected. Attempting to verify..."
        if gpg --verify "$file" 2>&1; then
            echo "Verification successful."
        else
            echo "Verification failed or encountered an error."
        fi
    else
        echo "This file doesn't appear to be a standard PGP file."
        echo "File type: $file_type"
        echo "Attempting general GPG verification..."
        if gpg --verify "$file" 2>&1; then
            echo "File verified successfully."
        else
            echo "Unable to verify this file. It might be encrypted or in an unsupported format."
        fi
    fi

    echo "Press Enter to continue..."
    read -r
}

delete_key() {
    while true; do
        echo "Enter the key ID to delete:"
        read -r keyid

        # Check if the user pressed Enter without entering a key ID
        if [ -z "$keyid" ]; then
            echo "Returning to Key Management menu..."
            return
        fi

        # Check if the key ID is valid by attempting to list the key
        if ! gpg --list-keys "$keyid" >/dev/null 2>&1; then
            echo "Unable to find the key: $keyid"
            echo "Please provide a valid key ID or press Enter to close..."
            continue
        fi

        echo "Do you want to delete this key? (y/n)"
        read -r response

        if [[ "$response" =~ ^[Yy]$ ]]; then
            # Delete both private and public keys
            gpg --delete-secret-and-public-key "$keyid"
            if [ $? -eq 0 ]; then
                echo "Key deleted successfully."
            else
                echo "Error: Failed to delete the key."
            fi
        else
            # Delete only the public key
            gpg --delete-key "$keyid"
            if [ $? -eq 0 ]; then
                echo "Key deleted successfully."
            else
                echo "Error: Failed to delete the key."
            fi
        fi

        echo "Press Enter to continue or ctrl+c to exit..."
        read -r
        return
    done
}


revoke_key() {
    echo "Enter the key ID to revoke:"
    read -r keyid
    gpg --gen-revoke --output "${keyid}_revocation.asc" "$keyid"
    echo "Revocation certificate generated. Please distribute it to inform others that the key has been revoked."
}

generate_revocation_certificate() {
    echo "Enter the key ID to generate a revocation certificate for:"
    read -r keyid
    gpg --output "${keyid}_revocation.asc" --gen-revoke "$keyid"
    echo "Revocation certificate generated and saved as ${keyid}_revocation.asc"
}

manage_subkeys() {
    echo "Enter the key ID to manage subkeys:"
    read -r keyid
    gpg --edit-key "$keyid"
    echo "Use 'addkey', 'key X' (where X is the subkey number), and 'expire' commands in the GPG prompt to manage subkeys."
}

change_passphrase() {
    echo "Enter the key ID to change passphrase:"
    read -r keyid
    gpg --passwd "$keyid"
}

modify_key_expiration() {
    echo "Enter the key ID to modify expiration:"
    read -r keyid

    # Key ID validation
    if [ -z "$keyid" ]; then
        echo "Key ID cannot be empty. Press Enter to continue..."
        read -r
        return
    fi

    # Check if the key ID exists in the keyring
    if ! gpg --list-keys "$keyid" >/dev/null 2>&1; then
        echo "Invalid key ID. Press Enter to continue..."
        read -r
        return
    fi

    echo "Enter new expiration period (e.g., 1y for one year, 6m for six months)."
    echo "Leave empty for no expiration:"
    read -r expiration

    # Create temp file for GPG commands
    temp_file=$(mktemp)

    if [ -z "$expiration" ]; then
        # If empty no expiration
        {
            echo "expire"
            echo ""
            echo "save"
        } > "$temp_file"
    else
        # If non empty uses the input duration
        {
            echo "expire"
            echo "$expiration"
            echo "save"
        } > "$temp_file"
    fi

    # Execute GPG with temp file's commands
    gpg --command-file "$temp_file" --edit-key "$keyid"

    # Capture the GPG commands output
    status=$?

    # Remove the temp file
    rm -f "$temp_file"

    if [ $status -eq 0 ]; then
        echo "Key expiration modified successfully. Press Enter to continue..."
    else
        echo "An error occurred while modifying the key expiration. Please check the errors above. Press Enter to continue..."
    fi

    read -r
}

clean_keyring() {
    expired_keys=$(gpg --list-keys | grep -E "^pub\s+\[expired: " | awk '{print $2}' | cut -d'/' -f2)

    if [ -z "$expired_keys" ]; then
        echo "The keyring is clean, nothing to do. Press Enter to continue..."
    else
        if gpg --delete-key --yes $expired_keys; then
            echo "Keyring clean successfully. Press Enter to continue..."
        else
            echo "An error occurred while cleaning the keyring. Please check the errors above. Press Enter to continue..."
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