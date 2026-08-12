select
 allocation_id,
 public_ip,
 region
from
 aws_vpc_eip
where
 association_id is null;
