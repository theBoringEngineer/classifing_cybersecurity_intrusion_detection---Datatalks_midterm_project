# Predicting the risk of being drawn into online sex work.

## Step 1: The dataset

- kaggle dataset:https://www.kaggle.com/datasets/dnkumars/cybersecurity-intrusion-detection-dataset
- Goal:
- Challenge:

## Setting up ENV (pipenv)

- python
- source testenv/bin/activate

## Setting up requirements file from virtual env (Optional)

- pip install -r requirements.txt
- pip freeze > requirements.txt

### Building/running docker file

- docker build -t [name] .

- docker run -it --rm --entrypoint=bash python:3.13.9-slim

- Note: [name] = intrusion-detector

## Running model on production server (Waitress)

- waitress-serve --listen=0.0.0.0:9696 predict:app

## Exposing and mapping docker env to service ports

- Add in docker file:
- - EXPOSE 9696
- - ENTRYPOINT [ "waitress-serve", "--listen=0.0.0.0:9696", "predict:app" ]
- Build image again: docker build -t [name] .
- Map conatainer and host ports: docker run -it -p 9696:9696 [name]

- Note: [name] = intrusion-detector

## Deploy to cloud(AWS:Elastic Beanstalk)

- Note: The aws service is a dependecy, hence, it should be installed in the local virtual env(venv/pipenv) rather than within the docker env.
- pip install [service/dependency]
- eb init -p docker -r eu-north-1 churn-serving
- Test it works locally: eb local run --port 9696

- Note: [service/dependency] = awsebcli
