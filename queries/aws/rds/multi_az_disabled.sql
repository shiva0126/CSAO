select
    db_instance_identifier,
    multi_az
from
    aws_rds_db_instance
where
    multi_az=false;
