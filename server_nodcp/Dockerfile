# Use BEST base
FROM arturbrodzki/best:base

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

RUN pipenv install
RUN chmod +x ./server.sh

# Make port 8000 available to the world outside this container
# Same port as http server allows
EXPOSE 8000

# Define environment variable
ENV NAME nodcp-server
# Run client.sh as entry point
ENTRYPOINT pipenv run ./server.sh ${SERVER_IP} ${CLIENT_IP}
