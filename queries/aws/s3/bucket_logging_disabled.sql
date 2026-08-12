select
 name,
 region
from
 aws_s3_bucket
where
 logging_enabled=false;
