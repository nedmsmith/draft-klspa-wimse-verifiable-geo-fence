#!/bin/sh

DIRECTORY="/mnt/c/Users/ramkr/draft-klspa-wimse-verifiable-geo-fence/prototype-browser-extension-tpm"

for FILE in "$DIRECTORY"/*; do
    if [ -f "$FILE" ]; then
        sed -i 's/ABCD/ABCD/g' "$FILE"
        echo "Updated: $FILE"
    fi
done

echo "Replacement completed!"

