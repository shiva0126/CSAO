select
    function_name
from
    aws_lambda_function
where
    dead_letter_config is null;
