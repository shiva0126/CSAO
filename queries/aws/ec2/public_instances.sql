select
  instance_id,
  instance_state,
  instance_type,
  public_ip_address,
  region,
  account_id
from
  aws_ec2_instance
where
  public_ip_address is not null;
