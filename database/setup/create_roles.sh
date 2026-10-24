#!/bin/bash
# create_roles.sh
# Runs roles.sql against our Docker database, using the values from .env.
# Run this from the main project folder:  bash database/setup/create_roles.sh

set -e   # stop if anything fails

# Load the values from .env (DB names, users and passwords)
set -a
source .env
set +a

# Send roles.sql into psql inside the container, passing in our values
docker exec -i evp-db psql -v ON_ERROR_STOP=1 \
  -U "$DB_ADMIN_USER" -d "$DB_NAME" \
  -v app_user="$DB_USER" \
  -v app_pass="$DB_PASSWORD" \
  -v db_name="$DB_NAME" \
  < database/setup/roles.sql

echo "App database user '$DB_USER' created with limited permissions."