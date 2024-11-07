#!/bin/bash

# Check if enough arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <output_directory> <output_filename>"
    exit 1
fi

# Get the output directory and file name from arguments
output_directory="$1"
output_filename="$2"

# Create the directory if it doesn't exist
mkdir -p "$output_directory"

# Define the JSON content
json_content='{
    "endianness": "little",
    "fields": [
        {
            "fields": [
                {
                    "name": "MessageType",
                    "size": 1,
                    "type": "unsigned_int"
                },
                {
                    "name": "Level",
                    "size": 3,
                    "type": "unsigned_int"
                },
                {
                    "name": "ObjectType",
                    "size": 4,
                    "type": "unsigned_int"
                }
            ],
            "name": "AlertDetails",
            "size": 8,
            "type": "bit_field"
        },
        {
            "name": "ObjectDistance",
            "size": 32,
            "type": "float_fixed"
        },
        {
            "name": "CarSpeed",
            "size": 32,
            "type": "unsigned_int"
        },
        {
            "name": "ObjectSpeed",
            "size": 32,
            "type": "unsigned_int"
        }
    ]
}'

# Create the full path for the output JSON file
output_file_path="$output_directory/$output_filename"

# Write the JSON content to the specified file
echo "$json_content" > "$output_file_path"

echo "JSON file created: $output_file_path"