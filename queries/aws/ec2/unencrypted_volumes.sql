select
 volume_id,
 size,
 encrypted,
 region,
 account_id
from
 aws_ebs_volume
where
 encrypted = false;
