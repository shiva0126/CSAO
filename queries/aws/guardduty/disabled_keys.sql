select
 key_id,
 key_state
from
 aws_kms_key
where
 key_state='Disabled';
