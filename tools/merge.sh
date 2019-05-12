#!/bin/bash

set -e
set -u

function error {
  echo -n -e '\e[31m\e[1m'
  echo -n "ERROR:" "$@"
  echo -e '\e[0m'
}

# if [[ -n $(git status -su) ]]; then
#   error 'Current tree is dirty, aborting merge request.'
#   git status
#   exit -1
# fi
# 
# git fetch
# if [[ $(git rev-parse HEAD) != $(git rev-parse @{u}) ]]; then
#   echo 'Current branch diverged from origin, aborting merge request.'
#   git status
#   exit -1
# fi
# 
BRANCH=$(git rev-parse --abbrev-ref HEAD)
PULL_URL=$(curl --fail --show-error --silent https://api.github.com/repos/sarum90/qjsonrs/pulls \
  | jq -r --arg branch "${BRANCH}" \
  '.[] | {url: .url, branch: .head.ref} | select(.branch == $branch) | .url')

echo $PULL_URL

TMPDIR=$(mktemp -d)
function finish {
  rm -rf "${TMPDIR}"
}
trap finish EXIT

PR_JSON_FILE="${TMPDIR}/pr.json"
curl --silent "${PULL_URL}" > "${PR_JSON_FILE}"

COMMIT_FILE="${TMPDIR}/COMMIT_EDITMSG"
TITLE=$(jq -r .title "${PR_JSON_FILE}")
BODY=$(jq -r .body "${PR_JSON_FILE}")
BASE=$(jq -r .base.ref "${PR_JSON_FILE}")
truncate -s 0 "${COMMIT_FILE}"
echo "${TITLE}" >> "${COMMIT_FILE}"
echo >> "${COMMIT_FILE}"
echo "${BODY}" | fold -w 80 -s >> "${COMMIT_FILE}"
"${EDITOR}" "${COMMIT_FILE}"
if [[ -z $(grep -v '^#' "${COMMIT_FILE}" | tr -d '[:space:]') ]]; then
  error "Aborting due to empty commit message"
  exit -1
fi
echo "Merging with commit message:"
cat "${COMMIT_FILE}"
#cat ${PR_JSON_FILE}
