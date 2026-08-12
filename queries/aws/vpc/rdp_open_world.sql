select
    group_id,
    group_name,
    from_port,
    cidr_ip
from
    aws_vpc_security_group_rule
where
    from_port = 3389
and
    cidr_ip='0.0.0.0/0';
