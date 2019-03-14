# Use BEST base image
FROM arturbrodzki/best:base

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install pipenv requirements
RUN pipenv install
RUN chmod +x ./client.sh
RUN chmod +x ./download_file.sh

# Delete musk_reloaded.png and antygona.txt files if accidentally put into the container
RUN rm -f musk.png
RUN rm -f antygona.txt

# Make required ports available to outsize world
EXPOSE 8000
EXPOSE 9000

# Define environment variable
ENV NAME dcp-client

# Run client.sh as entry point
ENTRYPOINT pipenv run ./client.sh ${SERVER_IP} ${CLIENT_IP} ${FILE_NAME} && pipenv run python -m http.server
