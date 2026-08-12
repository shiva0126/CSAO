select
 function_name,
 runtime
from
 aws_lambda_function
where
 runtime like '%python3.7%'
or
 runtime like '%nodejs12%';
