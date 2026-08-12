select
 db_instance_identifier,
 backup_retention_period
from
 aws_rds_db_instance
where
 backup_retention_period=0;
