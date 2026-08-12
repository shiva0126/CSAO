select
  group_id,
  group_name,
  region,
  ip_permission ->> 'FromPort' as from_port,
  ip_permission ->> 'ToPort' as to_port,
  ip_permission ->> 'IpProtocol' as protocol
from
  aws_vpc_security_group_rule
where
  cidr_ipv4 = '0.0.0.0/0';
