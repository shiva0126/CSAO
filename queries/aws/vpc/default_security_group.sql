select
 group_id,
 group_name,
 vpc_id
from
 aws_vpc_security_group
where
 group_name='default';
