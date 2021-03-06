#!/bin/bash

set -e
set -u

function error {
  echo -n -e '\e[31m\e[1m'
  echo -n "ERROR:" "$@"
  echo -e '\e[0m'
}

CURL="curl --fail --show-error --silent"

if [[ -e ~/.gittoken ]]; then
  CURL+=" -u $(cat ~/.gittoken):"
fi

if [[ -n $(git status -su) ]]; then
  error 'Current tree is dirty, aborting merge request.'
  git status
  exit -1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)

git fetch
if [[ $(git rev-parse HEAD) != $(git rev-parse @{u}) && $(git rev-parse HEAD) != $(git rev-parse origin/${BRANCH}) ]]; then
  error 'Current branch diverged from origin, aborting merge request.'
  git status
  exit -1
fi

if [[ ${BRANCH} == "master" ]]; then
  error 'Refusing to attempt to merge master into master.'
  exit -1
fi


PULL_URL=$(${CURL} https://api.github.com/repos/sarum90/qjsonrs/pulls \
  | jq -r --arg branch "${BRANCH}" \
  '.[] | {url: .url, branch: .head.ref} | select(.branch == $branch) | .url')

if [[ ${PULL_URL} == "" ]]; then
  error 'Could not find pull request based on this branch.'
  echo
  echo "Visit: https://github.com/sarum90/qjsonrs/pull/new/${BRANCH} to create one."
  exit -1
fi

TMPDIR=$(mktemp -d)
function finish {
  rm -rf "${TMPDIR}"
}
trap finish EXIT

PR_JSON_FILE="${TMPDIR}/pr.json"
${CURL} "${PULL_URL}" > "${PR_JSON_FILE}"

COMMIT_EDIT_FILE="${TMPDIR}/COMMIT_EDITMSG"
COMMIT_FILE="${TMPDIR}/COMMIT"
TITLE=$(jq -r .title "${PR_JSON_FILE}")
NUMBER=$(jq -r .number "${PR_JSON_FILE}")
BODY=$(jq -r .body "${PR_JSON_FILE}")
BASE=$(jq -r .base.ref "${PR_JSON_FILE}")
COMMIT_SHA=$(jq -r .head.sha "${PR_JSON_FILE}")

truncate -s 0 "${COMMIT_EDIT_FILE}"
echo "# Commit message for this merge. Generated from PR title / body." >> "${COMMIT_EDIT_FILE}"
echo "# There will be a confirmation before merge is executed." >> "${COMMIT_EDIT_FILE}"
echo "#" >> "${COMMIT_EDIT_FILE}"
echo "# Note: if the merge fails for any reason this file will not be saved." >> "${COMMIT_EDIT_FILE}"
echo "# Consider changing the description on Github rather than editing here." >> "${COMMIT_EDIT_FILE}"
echo "${TITLE} (#${NUMBER})" >> "${COMMIT_EDIT_FILE}"
echo >> "${COMMIT_EDIT_FILE}"
echo "${BODY}" | fold -w 80 -s >> "${COMMIT_EDIT_FILE}"
"${EDITOR}" "${COMMIT_EDIT_FILE}"
grep -v '^#' "${COMMIT_EDIT_FILE}" > "${COMMIT_FILE}"
if [[ -z $(cat "${COMMIT_FILE}" | tr -d '[:space:]') ]]; then
  error "Aborting due to empty commit message"
  exit -1
fi

echo "Merging with commit message:"
echo "==="
cat "${COMMIT_FILE}"
echo "==="
read -p "Are you sure [y/N]? " -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
  error "Exit on user request"
  exit -1
fi

STATUS=$(${CURL} https://api.github.com/repos/sarum90/qjsonrs/commits/${COMMIT_SHA}/status | jq -r '.state')
if [[ ${STATUS} == "pending" ]]; then
  echo "Current github status is pending."
  read -p "Do you want to wait til that completes [y/N]? " -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]
  then
    error "Will not merge pending branch"
    exit -1
  fi
  while [[ ${STATUS} == "pending" ]]; do
    echo "Waiting 5 sec... (CTRL-C is safe to do whenever)"
    sleep 5
    STATUS=$(${CURL} https://api.github.com/repos/sarum90/qjsonrs/commits/${COMMIT_SHA}/status | jq -r '.state')
    echo "New status: ${STATUS}"
  done
fi

if [[ ${STATUS} != "success" ]]; then
  error "Will not merge commit with status ${STATUS}, must be success"
  exit -1
fi


# Now we are changing working tree, be very explicit about it:
set -x

git checkout "${BASE}"
git pull origin
git merge --squash --no-commit  "${BRANCH}"
git commit -F "${COMMIT_FILE}"
git push origin
git push origin ":${BRANCH}"
git branch -D "${BRANCH}"
