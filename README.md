# StormGlass

**Know your worst day before it happens.**

StormGlass builds a model of an organisation's environment, simulates severe-but-plausible cyber scenarios against it, and turns the outcomes into quantified impact and control evidence.

## What works today

StormGlass can read a description of a cloud environment, build a graph of it, and find every route from the internet to sensitive data. It needs only Python 3 and a Terraform plan exported as JSON. Nothing is deployed and no cloud account is used.

```
cd environments/fintech-v0
python read_env.py plan.json      # inventory and individual flaws
python find_paths.py plan.json    # attack paths to sensitive data
```

Sample output from `find_paths.py` on the `fintech-v0` reference environment:

```
  TARGET: customer-records  (aws_s3_bucket)

  Path 1  (3 steps)
    start: the internet
    1. -> sg-web-01  [aws_instance]
         because port 443 is open to 0.0.0.0/0
         also    port 22 is open to 0.0.0.0/0
    2. -> sg-app-role  [aws_iam_role]
         because instance profile 'sg-app-profile' lets it act as this role
    3. -> customer-records  [aws_s3_bucket]
         because policy 'sg-app-policy' allows 's3:*' on every resource
```

A path means each step is permitted by the configuration. It does not mean the step is easy for an attacker. Likelihood and cost are the job of the later modules.

## Reference environments

Both are small, fictional, fintech-shaped AWS environments written in Terraform. They exist only to be planned and analysed.

| Environment | What it is | Paths to customer data |
| --- | --- | --- |
| `fintech-v0` | Deliberately flawed: SSH open to the internet, one role shared by the web and backend servers, wildcard S3 access | 2 |
| `fintech-v1` | The same environment with one fix: the web server gets its own role with no S3 access | 1 |

Running the same tool on both shows what one control changes. The fix in v1 closes the direct path from the web server. The route through the backend server survives it.

To regenerate a plan file from an environment folder:

```
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

## Modules

1. Twin builder
2. Scenario library
3. Simulation engine
4. Impact model
5. Control and evidence mapper
6. Narrative layer
7. Agent conduct lab, including rogue-agent containment and kill-switch testing
8. Threat behaviour library
9. Social engineering layer

The scripts above are the first slice of the twin builder and the simulation engine.

## Status

Early development. M.S. Cybersecurity project, University of Delaware.
