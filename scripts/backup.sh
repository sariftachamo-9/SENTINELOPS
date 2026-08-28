#!/bin/bash
# Get the absolute path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$PROJECT_DIR/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "📂 Project Directory: $PROJECT_DIR"
echo "📂 Backup Directory: $BACKUP_DIR"

mkdir -p "$BACKUP_DIR"

# Backup database
if [ -f "$PROJECT_DIR/soc_data.db" ]; then
    cp "$PROJECT_DIR/soc_data.db" "$BACKUP_DIR/soc_data_$TIMESTAMP.db"
    echo "✅ Database backed up: soc_data_$TIMESTAMP.db"
else
    echo "⚠️ No database found to backup"
fi

# Backup config
if [ -d "$PROJECT_DIR/config" ]; then
    tar -czf "$BACKUP_DIR/config_$TIMESTAMP.tar.gz" -C "$PROJECT_DIR" config/
    echo "✅ Configuration backed up: config_$TIMESTAMP.tar.gz"
fi

# Backup logs
if [ -d "$PROJECT_DIR/logs" ]; then
    tar -czf "$BACKUP_DIR/logs_$TIMESTAMP.tar.gz" -C "$PROJECT_DIR" logs/
    echo "✅ Logs backed up: logs_$TIMESTAMP.tar.gz"
fi

# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "*.db" -mtime +7 -delete 2>/dev/null
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete 2>/dev/null

echo "✅ Backup complete - $TIMESTAMP"
echo "📂 Backups stored in: $BACKUP_DIR"
