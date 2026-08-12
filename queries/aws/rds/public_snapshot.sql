select
    db_snapshot_identifier,
    snapshot_type
from
    aws_rds_db_snapshot
where
    snapshot_type='public';
