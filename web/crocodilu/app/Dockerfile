# base image
FROM python:3.9-slim-buster

# set working directory
WORKDIR /app

# copy requirements
COPY requirements.txt requirements.txt

# install dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# copy app files
COPY . .

# expose port 5000
EXPOSE 5000

# set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# start the server
CMD ["flask", "run", "--host=0.0.0.0"]