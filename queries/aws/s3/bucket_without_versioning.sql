select
 name,
 region
from
 aws_s3_bucket
where
 versioning_enabled=false;
