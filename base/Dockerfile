# Use an official Python runtime as a parent image
FROM python:3.5-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install APT dependencies
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y iptables curl build-essential python-dev libnetfilter-queue-dev tshark iputils-ping htop procps -y

# Install pipenv and Python dependencies
RUN pip install pipenv
RUN pipenv install

# Define environment variable
ENV NAME best-base

# Show control message
ENTRYPOINT echo "BEST-base: all done!"
