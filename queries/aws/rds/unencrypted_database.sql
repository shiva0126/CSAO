select
 db_instance_identifier,
 engine,
 storage_encrypted
from
 aws_rds_db_instance
where
 storage_encrypted=false;
