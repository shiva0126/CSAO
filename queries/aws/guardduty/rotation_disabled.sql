select
 key_id,
 enabled
from
 aws_kms_key
where
 enabled=false;
