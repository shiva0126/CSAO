select
    vpc_id
from
    aws_vpc
where
    flow_logs is null;
