#!/usr/bin/env bash

deb http://apt.postgresql.org/pub/repos/apt/ precise-pgdg main > /etc/apt/sources.list.d/pgdg.list
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
apt-get update
apt-get install -y python-pip python-dev libpq-dev tmux vim
pip install google-api-python-client flask flask-script psycopg2
echo SELECTED_EDITOR=\"/usr/bin/vim.basic\" > ~/.selected_editor