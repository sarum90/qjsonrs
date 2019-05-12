#!/bin/bash

set -e
set -u

if [[ -n $(git status -s) ]]; then
  echo 'Current tree is dirty, aborting merge request.'
  git status
  exit -1
fi

git fetch
git status

BRANCH=$(git rev-parse --abbrev-ref HEAD)
PULL_URL=$(curl --silent https://api.github.com/repos/sarum90/qjsonrs/pulls \
  | jq -r --arg branch "${BRANCH}" \
  '.[] | {url: .url, branch: .head.ref} | select(.branch == $branch) | .url')

echo $PULL_URL
