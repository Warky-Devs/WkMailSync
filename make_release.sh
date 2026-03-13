#!/bin/bash

# Detect the latest version tag
latest_tag=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)

if [[ -z "$latest_tag" ]]; then
    suggested_version="v1.0.0"
else
    # Increment the patch version
    IFS='.' read -r major minor patch <<< "${latest_tag#v}"
    suggested_version="v${major}.${minor}.$((patch + 1))"
fi

echo "Latest tag: ${latest_tag:-none}"
echo "Suggested next version: $suggested_version"

read -p "Do you want to make a release version? (y/n): " make_release

if [[ $make_release =~ ^[Yy]$ ]]; then
    read -p "Enter the version number [$suggested_version]: " version
    version="${version:-$suggested_version}"

    # Validate the version number
    if ! [[ $version =~ ^(v)?([0-9]+\.){0,2}[0-9]+(\.[0-9]+)?(\.beta)?$ ]]; then
        echo "Invalid version number format. Please use a valid format like 'v1.0.0'"
        exit 1
    fi

    # Prepend 'v' to the version if it doesn't start with it
    if ! [[ $version =~ ^v ]]; then
        version="v$version"
    fi

    # Build tag message with recent commits since last tag
    if [[ -n "$latest_tag" ]]; then
        commit_log=$(git log "${latest_tag}..HEAD" --oneline --no-decorate)
    else
        commit_log=$(git log --oneline --no-decorate -20)
    fi

    tag_message="Released $version

Changes since ${latest_tag:-beginning}:
$commit_log"

    # Create an annotated tag
    git tag -a "$version" -m "$tag_message"

    # Push the tag to the remote repository
    git push origin "$version"

    echo "Tag $version created and pushed to the remote repository."
else
    echo "No release version created."
fi
