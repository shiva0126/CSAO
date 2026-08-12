select
 name,
 region
from
 aws_s3_bucket
where
 server_side_encryption_configuration is null;
