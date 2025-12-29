#!/bin/bash
# PostgreSQL Backup Script with Rotation
# Keeps only the last 3 backups to save space

set -e

BACKUP_DIR="/home/gsrpdadmin/backups/postgres"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONTAINER_NAME="secretsnipe-postgres"
POSTGRES_USER="secretsnipe"
KEEP_BACKUPS=3

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "Starting PostgreSQL backup at $(date)"

# Backup all databases
docker exec "$CONTAINER_NAME" pg_dumpall -U "$POSTGRES_USER" | gzip > "$BACKUP_DIR/postgres_all_${TIMESTAMP}.sql.gz"

# Backup individual databases (wiki and secretsnipe)
docker exec "$CONTAINER_NAME" pg_dump -U "$POSTGRES_USER" -d wiki -F c | gzip > "$BACKUP_DIR/wiki_${TIMESTAMP}.dump.gz"

docker exec "$CONTAINER_NAME" pg_dump -U "$POSTGRES_USER" -d secretsnipe -F c | gzip > "$BACKUP_DIR/secretsnipe_${TIMESTAMP}.dump.gz"

echo "Backups created successfully"

# Cleanup old backups - keep only the last $KEEP_BACKUPS
echo "Cleaning up old backups (keeping last $KEEP_BACKUPS)..."

# Remove old postgres_all backups
ls -t "$BACKUP_DIR"/postgres_all_*.sql.gz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f

# Remove old wiki backups
ls -t "$BACKUP_DIR"/wiki_*.dump.gz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f

# Remove old secretsnipe backups
ls -t "$BACKUP_DIR"/secretsnipe_*.dump.gz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f

# Show current backup status
echo ""
echo "Current backups:"
ls -lh "$BACKUP_DIR"
echo ""
echo "Backup completed at $(date)"
