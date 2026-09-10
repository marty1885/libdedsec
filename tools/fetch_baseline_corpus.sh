#!/bin/sh
# Public-domain Project Gutenberg texts in distinct styles and periods.
set -eu

target=${1:-corpus/gutenberg}
mkdir -p "$target"
fetch() {
    name=$1
    url=$2
    curl --fail --location --retry 3 --silent --show-error "$url" -o "$target/$name"
}
fetch alice.txt https://www.gutenberg.org/files/11/11-0.txt
fetch frankenstein.txt https://www.gutenberg.org/files/84/84-0.txt
fetch moby_dick.txt https://www.gutenberg.org/files/2701/2701-0.txt
fetch pride_and_prejudice.txt https://www.gutenberg.org/files/1342/1342-0.txt
