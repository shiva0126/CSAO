select
 name,
 region,
 account_id
from
 aws_s3_bucket
where
 block_public_acls = false
or
 block_public_policy = false;
