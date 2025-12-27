# JS Azure Functions Package

### Contents

- verifyJwt
  - Built for specific use with the Riata repo
  - Takes a JWT, public key, and raw body of an HTTP request then verifies its authenticity and integrity

### Installation

1. [Create a function app](https://learn.microsoft.com/en-us/azure/azure-functions/functions-create-function-app-portal?tabs=core-tools&pivots=flex-consumption-plan)
2. [Fork this repo](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo)
3. [Deploy the forked repo to the function app](https://learn.microsoft.com/en-us/azure/azure-functions/functions-continuous-deployment?tabs=github%2Cgithub-actions%2Cazure-portal)
4. [Secure the function endpoints](https://learn.microsoft.com/en-us/azure/azure-functions/function-keys-how-to?tabs=azure-portal) (keys are easiest)
5. Locate the function URL and use where desired
